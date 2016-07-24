/*
   This is an example on how to parse OVAL files for getting vulnerabilities definitions
   for an RPM based distribution.

   More info on OVAL: https://oval.cisecurity.org/
   OVAL files for SUSE
   http://ftp.suse.com/pub/projects/security/oval/
   OVAL files for RedHat
   https://www.redhat.com/security/data/oval/
*/
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html
type oval_definitions struct {
	Generator      generator       `xml:"generator"`
	Definitions    []definition    `xml:"definitions>definition"`
	RPMInfoTests   []rpmInfoTest   `xml:"tests>rpminfo_test"`
	RPMInfoObjects []rpmInfoObject `xml:"objects>rpminfo_object"`
	RPMInfoState   []rpmInfoState  `xml:"states>rpminfo_state"`
	/* Other elements defined in the specification we are not using here:
	variables
	ds:Signature
	*/
}

func (o *oval_definitions) String() string {
	result := ""
	result += "++ Generator\n" + o.Generator.String() + "\n\n"
	for i := 0; i < len(o.Definitions); i++ {
		result += "Metadata:Title: " + o.Definitions[i].Metadata.Title + "\n"
		result += "Metadata:Description: " + o.Definitions[i].Metadata.Description + "\n"
		for j := 0; j < len(o.Definitions[i].Metadata.References); j++ {
			result += "Reference:source: " + o.Definitions[i].Metadata.References[j].Source + "\n"
			result += "Reference:url: " + o.Definitions[i].Metadata.References[j].URI + "\n"
		}
		result += o.Definitions[i].Criteria.String()
	}
	result += "\n"
	for i := 0; i < len(o.RPMInfoTests); i++ {
		result += "Tests: " + o.RPMInfoTests[i].String() + "\n"
	}
	for i := 0; i < len(o.RPMInfoState); i++ {
		result += "States: " + o.RPMInfoState[i].String() + "\n"
	}
	for i := 0; i < len(o.RPMInfoObjects); i++ {
		result += "Objects: " + o.RPMInfoObjects[i].String() + "\n"
	}
	return result
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-common-schema.html#GeneratorType
type generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	Timestamp      string `xml:"timestamp"`
	Any            string `xml:"xsd:any"`
}

func (g *generator) String() string {
	return fmt.Sprintf("Product name: %s\nProduct Version %s\nSchema Version %s\nTimestamp %s\nOther %s", g.ProductName, g.ProductVersion, g.SchemaVersion, g.Timestamp, g.Any)
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/linux-definitions-schema.html
// http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#TestType.
type rpmInfoTest struct {
	Id      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Comment string `xml:"comment,attr"`
	// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-common-schema.html#CheckEnumeration
	// Possible values are
	//  all
	//  at least one
	//  none satisfy
	//  only one
	Check     string    `xml:"check,attr"`
	ObjectRef objectRef `xml:"object"`
	StateRef  stateRef  `xml:"state"`
	/* Other elements defined in the specification that we are not using here:
	check_existence
	state_operator
	deprecated
	ds:Signature
	notes
	*/
}

func (r *rpmInfoTest) String() string {
	result := ""
	result += "Id : " + r.Id + "\n"
	result += "Version: " + r.Version + "\n"
	result += "Comment: " + r.Comment + "\n"
	result += "Check: " + r.Check + "\n"
	result += "ObjectRef: " + r.ObjectRef.Id + "\n"
	result += "SateRef: " + r.StateRef.Id + "\n"
	return result
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#ObjectRefType
type objectRef struct {
	Id string `xml:"object_ref,attr"`
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#StateRefType
type stateRef struct {
	Id string `xml:"state_ref,attr"`
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/linux-definitions-schema.html
// http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#ObjectType
type rpmInfoObject struct {
	Id      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Name    string `xml:"name"`
	/* Others elements defined in the specification that we are not using here:
	behaviours
	oval-def:filter
	comment
	deprecated
	*/
}

func (r *rpmInfoObject) String() string {
	return fmt.Sprintf("Id: %s Version: %s Name: %s", r.Id, r.Version, r.Name)
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#StateType
// http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/linux-definitions-schema.html
type rpmInfoState struct {
	Id      string  `xml:"id,attr"`
	Version string  `xml:"version,attr"`
	Evr     evr     `xml:"evr"`
	Ver     version `xml:"version"`
	/* Other elements defined in the specification that we are not using here:
	name, arch, epoch, release, signature_keyid, extended_name, filepath,
	ds:Signature, notes, operator, comment, deprecated.*/
}

func (r *rpmInfoState) String() string {
	return fmt.Sprintf("Id: %s Version: %s\nEvr: %s %s %s\nVersion: %s %s", r.Id, r.Version, r.Evr.DataType, r.Evr.Operation, r.Evr.Value, r.Ver.Operation, r.Ver.Value)
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#EntityStateAnySimpleType
type version struct {
	// Expected operations within OVAL for version values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
	// I've seen a "pattern match" in redhat example code which is a OperationEnumeration. I think this should have been in the rpmInfoState>Operator instead
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#EntityStateEVRStringType
type evr struct {
	// Expected operations within OVAL for evr_string values are 'equals', 'not equal', 'greater than', 'greater than or equal', 'less than', and 'less than or equal'.
	DataType  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#DefinitionsType
type definition struct {
	Metadata metadata `xml:"metadata"`
	Criteria criteria `xml:"criteria"`
}

// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#MetadataType
type metadata struct {
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	References  []reference `xml:"reference"`
	Advisory    advisory    `xml:"advisory"`
	/*Other elements defined in the specification that we are not using here
	affected <- RHEL and SLES have values for this field
	xsd:any
	*/
}

/* RHEL has the advisory like this (this is for the xsd:any field in the metadata)
<advisory from="secalert@redhat.com">
        <severity>Moderate</severity>
        <rights>Copyright 2015 Red Hat, Inc.</rights>
        <issued date="2015-06-29"/>
        <updated date="2015-06-29"/>
        <cve href="https://access.redhat.com/security/cve/CVE-2015-0252">CVE-2015-0252</cve>
        <bugzilla href="https://bugzilla.redhat.com/1199103" id="1199103">CVE-2015-0252 xerces-c: crashes on malformed input</bugzilla>
    <affected_cpe_list>
        <cpe>cpe:/o:redhat:enterprise_linux:7</cpe>
    </affected_cpe_list>
</advisory> */
type advisory struct {
	From     string `xml:"from,attr"`
	Severity string `xml:"severity"`
	Rights   string `xml:"rights"`
	// Issued   date            `xml:"issued"`
	// Updated  date            `xml:"updated"`
	// CVE      cve             `xml:"cve"`
	// Bugzilla bugzilla        `xml:"bugzilla"`
	// Affected affectedCpeList `xml:"affected_cpe_list"`
}

func (a *advisory) String() string {
	return fmt.Sprintf("Advisory from: %s of severity %s with rights %s", a.From, a.Severity, a.Rights)
}

// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#ReferenceType
type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	RefId  string `xml:"ref_id,attr"`
}

// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#CriteriaType
// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-common-schema.html#OperatorEnumeration
type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
	/* Other elements defined in the specification that we are not using here
	applicability_check
	negate
	comment
	extend_definition
	*/
}

func (c *criteria) String() string {
	result := "Criteria operator: " + c.Operator
	for i := 0; i < len(c.Criterions); i++ {
		result += "Criterion: " + c.Criterions[i].TestRef + " " + c.Criterions[i].Comment + "\n"
	}
	for j := 0; j < len(c.Criterias); j++ {
		result += c.Criterias[j].String()
	}
	return result
}

// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html#CriterionType
// see: http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-common-schema.html#TestIDPattern
type criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
	/* Other elements defined in the specification that we are not using here
	applicability_check
	negate
	*/
}

func usage_and_exit(err error) {
	fmt.Println(err.Error())
	fmt.Println("usage: %s filename.xml", os.Args[0])
	fmt.Println(" where filename.xml is oval xml file to parse")
	os.Exit(-1)
}

type myError struct {
	Message string
}

func (e *myError) Error() string {
	return e.Message
}

func getArgs() (string, error) {
	if len(os.Args) != 2 {
		return "", &myError{Message: "wrong # of arguments"}
	}
	return os.Args[1], nil
}

func main() {
	file, err := getArgs()
	if err != nil {
		usage_and_exit(err)
	}
	fmt.Println("Parsing file ", file)
	xmlFile, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()
	data, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		log.Fatal(err)
	}
	v := oval_definitions{}
	err = xml.Unmarshal(data, &v)
	if err != nil {
		fmt.Println("Error unmarshalling", err)
		return
	}
	fmt.Println(&v)
}
