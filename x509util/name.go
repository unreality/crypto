package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"

	"github.com/pkg/errors"
)

// Name is the JSON representation of X.501 type Name, used in the X.509 subject
// and issuer fields.
type Name struct {
	Country            MultiString `json:"country,omitempty"`
	Organization       MultiString `json:"organization,omitempty"`
	OrganizationalUnit MultiString `json:"organizationalUnit,omitempty"`
	DomainController   MultiString `json:"domainController,omitempty"`
	Locality           MultiString `json:"locality,omitempty"`
	Province           MultiString `json:"province,omitempty"`
	StreetAddress      MultiString `json:"streetAddress,omitempty"`
	PostalCode         MultiString `json:"postalCode,omitempty"`
	SerialNumber       string      `json:"serialNumber,omitempty"`
	CommonName         string      `json:"commonName,omitempty"`
	Surname            string      `json:"surname,omitempty"`
	GivenName          string      `json:"givenName,omitempty"`
	Title              string      `json:"title,omitempty"`
	UID                string      `json:"userID,omitempty"`
}

var (
	oidUID                = []int{0, 9, 2342, 19200300, 100, 1, 1}
	oidDC                 = []int{0, 9, 2342, 19200300, 100, 1, 25}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSurname            = []int{2, 5, 4, 4}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidCountry            = []int{2, 5, 4, 6}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidTitle              = []int{2, 5, 4, 12}
	oidPostalCode         = []int{2, 5, 4, 17}
	oidGivenName          = []int{2, 5, 4, 42}
)

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Name struct or a string as just the subject common name.
func (n *Name) UnmarshalJSON(data []byte) error {
	if cn, ok := maybeString(data); ok {
		n.CommonName = cn
		return nil
	}

	type nameAlias Name
	var nn nameAlias
	if err := json.Unmarshal(data, &nn); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*n = Name(nn)
	return nil
}

// Subject is the JSON representation of the X.509 subject field.
type Subject Name

func newSubject(n pkix.Name) Subject {
	return Subject{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Subject struct or a string as just the subject common name.
func (s *Subject) UnmarshalJSON(data []byte) error {
	var name Name
	if err := name.UnmarshalJSON(data); err != nil {
		return err
	}
	*s = Subject(name)
	return nil
}

// Set sets the subject in the given certificate.
func (s Subject) Set(c *x509.Certificate) {
	//c.Subject = pkix.Name{
	//	Country:            s.Country,
	//	Organization:       s.Organization,
	//	OrganizationalUnit: s.OrganizationalUnit,
	//	Locality:           s.Locality,
	//	Province:           s.Province,
	//	StreetAddress:      s.StreetAddress,
	//	PostalCode:         s.PostalCode,
	//	SerialNumber:       s.SerialNumber,
	//	CommonName:         s.CommonName,
	//}

	c.Subject = pkix.Name{}

	for _, country := range s.Country {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidCountry,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(country),
			},
		})
	}

	for _, locality := range s.Locality {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidLocality,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(locality),
			},
		})
	}

	for _, province := range s.Province {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidProvince,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(province),
			},
		})
	}

	for _, streetAddress := range s.StreetAddress {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidStreetAddress,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(streetAddress),
			},
		})
	}

	for _, postalCode := range s.PostalCode {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidPostalCode,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(postalCode),
			},
		})
	}

	for _, org := range s.Organization {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidOrganization,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(org),
			},
		})
	}

	for _, dc := range s.DomainController {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidDC,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(dc),
			},
		})
	}

	for _, orgUnit := range s.OrganizationalUnit {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidOrganizationalUnit,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(orgUnit),
			},
		})
	}

	if s.Title != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidTitle,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.Title),
			},
		})
	}

	if s.GivenName != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidGivenName,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.GivenName),
			},
		})
	}

	if s.Surname != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidSurname,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.Surname),
			},
		})
	}

	if s.CommonName != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidCommonName,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.CommonName),
			},
		})
	}

	if s.SerialNumber != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidSerialNumber,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.SerialNumber),
			},
		})
	}

	if s.UID != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidUID,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(s.UID),
			},
		})
	}

}

// Issuer is the JSON representation of the X.509 issuer field.
type Issuer Name

// nolint:unused
func newIssuer(n pkix.Name) Issuer {
	return Issuer{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals a JSON
// object in the Issuer struct or a string as just the subject common name.
func (i *Issuer) UnmarshalJSON(data []byte) error {
	var name Name
	if err := name.UnmarshalJSON(data); err != nil {
		return err
	}
	*i = Issuer(name)
	return nil
}

// Set sets the issuer in the given certificate.
func (i Issuer) Set(c *x509.Certificate) {
	c.Issuer = pkix.Name{
		Country:            i.Country,
		Organization:       i.Organization,
		OrganizationalUnit: i.OrganizationalUnit,
		Locality:           i.Locality,
		Province:           i.Province,
		StreetAddress:      i.StreetAddress,
		PostalCode:         i.PostalCode,
		SerialNumber:       i.SerialNumber,
		CommonName:         i.CommonName,
	}
}
