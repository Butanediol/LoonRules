package main

import (
	"bufio"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	RuleTypeDomain     string = "domain"
	RuleTypeFullDomain string = "full"
	RuleTypeKeyword    string = "keyword"
	RuleTypeRegexp     string = "regexp"
	RuleTypeInclude    string = "include"
)

var (
	dataPath  = flag.String("datapath", "../domain-list-community/data", "Path to domain-list-community data directory")
	geoipPath = flag.String("geoippath", "", "Path to geoip text directory (optional)")
	outputDir = flag.String("outputdir", "./output", "Directory to place generated Loon rules files")
)

type Entry struct {
	Type  string
	Value string
	Attrs []string
	Plain string
}

type Inclusion struct {
	Source    string
	MustAttrs []string
	BanAttrs  []string
}

type ParsedList struct {
	Name       string
	Inclusions []*Inclusion
	Entries    []*Entry
}

type Processor struct {
	plMap     map[string]*ParsedList
	finalMap  map[string][]*Entry
	cirIncMap map[string]bool
}

func v2flyToLoonRule(entry *Entry) string {
	var ruleType string
	switch entry.Type {
	case RuleTypeDomain:
		ruleType = "DOMAIN-SUFFIX"
	case RuleTypeFullDomain:
		ruleType = "DOMAIN"
	case RuleTypeKeyword:
		ruleType = "DOMAIN-KEYWORD"
	case RuleTypeRegexp:
		ruleType = "DOMAIN-REGEX"
	default:
		return ""
	}
	return fmt.Sprintf("%s,%s", ruleType, entry.Value)
}

func writeLoonRuleFile(listName string, entries []*Entry, ipRules []string, outputDir string) error {
	filename := strings.ToLower(listName) + ".list"
	filePath := filepath.Join(outputDir, filename)

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, entry := range entries {
		rule := v2flyToLoonRule(entry)
		if rule != "" {
			fmt.Fprintln(w, rule)
		}
	}
	for _, rule := range ipRules {
		fmt.Fprintln(w, rule)
	}
	return w.Flush()
}

func loadGeoIPData(dir string) (map[string][]string, error) {
	result := make(map[string][]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasSuffix(base, ".txt") {
			return nil
		}
		name := strings.ToLower(strings.TrimSuffix(base, ".txt"))

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		var rules []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var ruleType string
			if strings.Contains(line, ":") {
				ruleType = "IP-CIDR6"
			} else {
				ruleType = "IP-CIDR"
			}
			rules = append(rules, fmt.Sprintf("%s,%s,no-resolve", ruleType, line))
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading %q: %w", path, err)
		}
		if len(rules) > 0 {
			result[name] = rules
		}
		return nil
	})
	return result, err
}

func parseEntry(line string) (*Entry, []string, error) {
	entry := new(Entry)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return entry, nil, fmt.Errorf("empty line")
	}

	typ, val, isTypeSpecified := strings.Cut(parts[0], ":")
	typ = strings.ToLower(typ)
	if !isTypeSpecified {
		if !validateDomainChars(typ) {
			return entry, nil, fmt.Errorf("invalid domain: %q", typ)
		}
		entry.Type = RuleTypeDomain
		entry.Value = typ
	} else {
		switch typ {
		case RuleTypeRegexp:
			if _, err := regexp.Compile(val); err != nil {
				return entry, nil, fmt.Errorf("invalid regexp %q: %w", val, err)
			}
			entry.Type = RuleTypeRegexp
			entry.Value = val
		case RuleTypeInclude:
			entry.Type = RuleTypeInclude
			entry.Value = strings.ToUpper(val)
			if !validateSiteName(entry.Value) {
				return entry, nil, fmt.Errorf("invalid included list name: %q", entry.Value)
			}
		case RuleTypeDomain, RuleTypeFullDomain, RuleTypeKeyword:
			entry.Type = typ
			entry.Value = strings.ToLower(val)
			if !validateDomainChars(entry.Value) {
				return entry, nil, fmt.Errorf("invalid domain: %q", entry.Value)
			}
		default:
			return entry, nil, fmt.Errorf("invalid type: %q", typ)
		}
	}

	var affs []string
	for _, part := range parts[1:] {
		switch part[0] {
		case '@':
			attr := strings.ToLower(part[1:])
			if !validateAttrChars(attr) {
				return entry, affs, fmt.Errorf("invalid attribute: %q", attr)
			}
			entry.Attrs = append(entry.Attrs, attr)
		case '&':
			aff := strings.ToUpper(part[1:])
			if !validateSiteName(aff) {
				return entry, affs, fmt.Errorf("invalid affiliation: %q", aff)
			}
			affs = append(affs, aff)
		default:
			return entry, affs, fmt.Errorf("invalid attribute/affiliation: %q", part)
		}
	}

	if entry.Type != RuleTypeInclude {
		slices.Sort(entry.Attrs)
		var plain strings.Builder
		plain.Grow(len(entry.Type) + len(entry.Value) + 10)
		plain.WriteString(entry.Type)
		plain.WriteByte(':')
		plain.WriteString(entry.Value)
		for i, attr := range entry.Attrs {
			if i == 0 {
				plain.WriteByte(':')
			} else {
				plain.WriteByte(',')
			}
			plain.WriteByte('@')
			plain.WriteString(attr)
		}
		entry.Plain = plain.String()
	}
	return entry, affs, nil
}

func validateDomainChars(domain string) bool {
	for i := range domain {
		c := domain[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validateAttrChars(attr string) bool {
	for i := range attr {
		c := attr[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '!' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func validateSiteName(name string) bool {
	for i := range name {
		c := name[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func (p *Processor) getOrCreateParsedList(name string) *ParsedList {
	pl, exist := p.plMap[name]
	if !exist {
		pl = &ParsedList{Name: name}
		p.plMap[name] = pl
	}
	return pl
}

func (p *Processor) loadData(listName string, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	pl := p.getOrCreateParsedList(listName)
	scanner := bufio.NewScanner(file)
	lineIdx := 0
	for scanner.Scan() {
		lineIdx++
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entry, affs, err := parseEntry(line)
		if err != nil {
			return fmt.Errorf("error in %q at line %d: %w", path, lineIdx, err)
		}

		if entry.Type == RuleTypeInclude {
			inc := &Inclusion{Source: entry.Value}
			for _, attr := range entry.Attrs {
				if attr[0] == '-' {
					inc.BanAttrs = append(inc.BanAttrs, attr[1:])
				} else {
					inc.MustAttrs = append(inc.MustAttrs, attr)
				}
			}
			for _, aff := range affs {
				apl := p.getOrCreateParsedList(aff)
				apl.Inclusions = append(apl.Inclusions, inc)
			}
			pl.Inclusions = append(pl.Inclusions, inc)
		} else {
			for _, aff := range affs {
				apl := p.getOrCreateParsedList(aff)
				apl.Entries = append(apl.Entries, entry)
			}
			pl.Entries = append(pl.Entries, entry)
		}
	}
	return nil
}

func isMatchAttrFilters(entry *Entry, incFilter *Inclusion) bool {
	if len(incFilter.MustAttrs) == 0 && len(incFilter.BanAttrs) == 0 {
		return true
	}
	if len(entry.Attrs) == 0 {
		return len(incFilter.MustAttrs) == 0
	}
	for _, m := range incFilter.MustAttrs {
		if !slices.Contains(entry.Attrs, m) {
			return false
		}
	}
	for _, b := range incFilter.BanAttrs {
		if slices.Contains(entry.Attrs, b) {
			return false
		}
	}
	return true
}

func polishList(roughMap map[string]*Entry) []*Entry {
	finalList := make([]*Entry, 0, len(roughMap))
	queuingList := make([]*Entry, 0, len(roughMap))
	domainsMap := make(map[string]bool)
	for _, entry := range roughMap {
		switch entry.Type {
		case RuleTypeRegexp, RuleTypeKeyword:
			finalList = append(finalList, entry)
		case RuleTypeDomain:
			domainsMap[entry.Value] = true
			if len(entry.Attrs) != 0 {
				finalList = append(finalList, entry)
			} else {
				queuingList = append(queuingList, entry)
			}
		case RuleTypeFullDomain:
			if len(entry.Attrs) != 0 {
				finalList = append(finalList, entry)
			} else {
				queuingList = append(queuingList, entry)
			}
		}
	}

	for _, qentry := range queuingList {
		isRedundant := false
		pd := qentry.Value
		if qentry.Type == RuleTypeFullDomain {
			pd = "." + pd
		}
		for {
			var hasParent bool
			_, pd, hasParent = strings.Cut(pd, ".")
			if !hasParent {
				break
			}
			if domainsMap[pd] {
				isRedundant = true
				break
			}
		}
		if !isRedundant {
			finalList = append(finalList, qentry)
		}
	}

	slices.SortFunc(finalList, func(a, b *Entry) int {
		return strings.Compare(a.Plain, b.Plain)
	})
	return finalList
}

func (p *Processor) resolveList(plname string) error {
	if _, pldone := p.finalMap[plname]; pldone {
		return nil
	}
	pl, plexist := p.plMap[plname]
	if !plexist {
		return fmt.Errorf("list %q not found", plname)
	}
	if p.cirIncMap[plname] {
		return fmt.Errorf("circular inclusion in: %q", plname)
	}
	p.cirIncMap[plname] = true
	defer delete(p.cirIncMap, plname)

	roughMap := make(map[string]*Entry)
	for _, dentry := range pl.Entries {
		roughMap[dentry.Plain] = dentry
	}
	for _, inc := range pl.Inclusions {
		if _, exist := p.plMap[inc.Source]; !exist {
			return fmt.Errorf("list %q includes a non-existent list: %q", plname, inc.Source)
		}
		if err := p.resolveList(inc.Source); err != nil {
			return err
		}
		for _, ientry := range p.finalMap[inc.Source] {
			if isMatchAttrFilters(ientry, inc) {
				roughMap[ientry.Plain] = ientry
			}
		}
	}
	p.finalMap[plname] = polishList(roughMap)
	return nil
}

func writeIndexHTML(names []string, outputDir string) error {
	tmpl, err := template.ParseFiles("index.html.tmpl")
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	f, err := os.Create(filepath.Join(outputDir, "index.html"))
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, struct {
		Names     []string
		Count     int
		UpdatedAt string
	}{
		Names:     names,
		Count:     len(names),
		UpdatedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	})
}

func run() error {
	dir := *dataPath
	fmt.Printf("using domain lists data in %q\n", dir)

	processor := &Processor{plMap: make(map[string]*ParsedList)}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		listName := strings.ToUpper(filepath.Base(path))
		if !validateSiteName(listName) {
			return fmt.Errorf("invalid list name: %q", listName)
		}
		return processor.loadData(listName, path)
	})
	if err != nil {
		return fmt.Errorf("failed to loadData: %w", err)
	}

	processor.finalMap = make(map[string][]*Entry, len(processor.plMap))
	processor.cirIncMap = make(map[string]bool)
	for plname := range processor.plMap {
		if err := processor.resolveList(plname); err != nil {
			return fmt.Errorf("failed to resolveList %q: %w", plname, err)
		}
	}

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var geoipMap map[string][]string
	if *geoipPath != "" {
		fmt.Printf("using geoip data in %q\n", *geoipPath)
		geoipMap, err = loadGeoIPData(*geoipPath)
		if err != nil {
			return fmt.Errorf("failed to loadGeoIPData: %w", err)
		}
	}

	// Collect the union of all names from both sources
	allNames := make(map[string]bool)
	for name := range processor.finalMap {
		allNames[strings.ToLower(name)] = true
	}
	for name := range geoipMap {
		allNames[name] = true
	}

	var listNames []string
	for name := range allNames {
		upperName := strings.ToUpper(name)
		domainEntries := processor.finalMap[upperName]
		ipRules := geoipMap[name]
		if len(domainEntries) == 0 && len(ipRules) == 0 {
			continue
		}
		if err := writeLoonRuleFile(name, domainEntries, ipRules, *outputDir); err != nil {
			fmt.Printf("failed to write list %q: %v\n", name, err)
			continue
		}
		listNames = append(listNames, name)
		fmt.Printf("list %q has been generated successfully.\n", name)
	}

	slices.Sort(listNames)
	if err := writeIndexHTML(listNames, *outputDir); err != nil {
		return fmt.Errorf("failed to write index.html: %w", err)
	}
	fmt.Println("index.html has been generated successfully.")

	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Printf("Fatal error: %v\n", err)
		os.Exit(1)
	}
}
