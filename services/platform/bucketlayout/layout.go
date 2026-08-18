package bucketlayout

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumKeyBytes     = 1024
	encryptionAlgorithm = "aws:kms"
)

var (
	ErrLayout          = errors.New("bucket layout rejected")
	bucketNamePattern  = regexp.MustCompile(`^zasp-product-data-[0-9a-f]{32}$`)
	accountIDPattern   = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern      = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	kmsKeyARNPattern   = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]{3,32}):([0-9]{12}):key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	safeSegmentPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

type Class string

const (
	ClassEvidence Class = "evidence"
	ClassExport   Class = "exports"
	ClassPolicy   Class = "policies"
)

type Configuration struct {
	BucketName string
	Region     string
	AccountID  string
	KMSKeyARN  string
}

type Encryption struct {
	Algorithm        string
	KMSKeyARN        string
	BucketKeyEnabled bool
}

type Layout struct {
	bucketName string
	region     string
	accountID  string
	kmsKeyARN  string
	valid      bool
}

func New(configuration Configuration) (Layout, error) {
	if !configurationValid(configuration) {
		return Layout{}, ErrLayout
	}
	return Layout{
		bucketName: configuration.BucketName,
		region:     configuration.Region,
		accountID:  configuration.AccountID,
		kmsKeyARN:  configuration.KMSKeyARN,
		valid:      true,
	}, nil
}

func (layout Layout) Validate() error {
	if !layout.valid || !configurationValid(Configuration{
		BucketName: layout.bucketName,
		Region:     layout.region,
		AccountID:  layout.accountID,
		KMSKeyARN:  layout.kmsKeyARN,
	}) {
		return ErrLayout
	}
	return nil
}

func (layout Layout) Configuration() Configuration {
	if layout.Validate() != nil {
		return Configuration{}
	}
	return Configuration{
		BucketName: layout.bucketName,
		Region:     layout.region,
		AccountID:  layout.accountID,
		KMSKeyARN:  layout.kmsKeyARN,
	}
}

func (layout Layout) Encryption() Encryption {
	if layout.Validate() != nil {
		return Encryption{}
	}
	return Encryption{Algorithm: encryptionAlgorithm, KMSKeyARN: layout.kmsKeyARN, BucketKeyEnabled: true}
}

func (layout Layout) WorkspacePrefix(scope domain.Scope) (string, error) {
	if layout.Validate() != nil || scope.Validate() != nil {
		return "", ErrLayout
	}
	value := workspacePrefix(scope)
	if !validBuiltValue(value, value, true) {
		return "", ErrLayout
	}
	return value, nil
}

func (layout Layout) Prefix(scope domain.Scope, class Class) (string, error) {
	if layout.Validate() != nil || scope.Validate() != nil || !class.valid() {
		return "", ErrLayout
	}
	root := workspacePrefix(scope)
	value := root + "environments/" + scope.EnvironmentID().String() + "/" + string(class) + "/"
	if !validBuiltValue(value, root, true) {
		return "", ErrLayout
	}
	return value, nil
}

func (layout Layout) Key(scope domain.Scope, class Class, reference domain.ProductID) (string, error) {
	if layout.Validate() != nil || scope.Validate() != nil || !class.valid() || !validProductID(reference) ||
		reference == scope.OrganizationID() || reference == scope.WorkspaceID() || reference == scope.EnvironmentID() {
		return "", ErrLayout
	}
	root := workspacePrefix(scope)
	value := root + "environments/" + scope.EnvironmentID().String() + "/" + string(class) + "/" + reference.String()
	if !validBuiltValue(value, root, false) {
		return "", ErrLayout
	}
	return value, nil
}

func configurationValid(configuration Configuration) bool {
	if !bucketNamePattern.MatchString(configuration.BucketName) ||
		!accountIDPattern.MatchString(configuration.AccountID) ||
		len(configuration.Region) > 32 || !regionPattern.MatchString(configuration.Region) {
		return false
	}
	matches := kmsKeyARNPattern.FindStringSubmatch(configuration.KMSKeyARN)
	if len(matches) != 5 || matches[2] != configuration.Region || matches[3] != configuration.AccountID {
		return false
	}
	return regionMatchesPartition(matches[1], configuration.Region)
}

func regionMatchesPartition(partition, region string) bool {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return partition == "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return partition == "aws-us-gov"
	case strings.HasPrefix(region, "us-iso-"), strings.HasPrefix(region, "us-isob-"),
		strings.HasPrefix(region, "eu-isoe-"), strings.HasPrefix(region, "us-isof-"):
		return false
	default:
		return partition == "aws"
	}
}

func (class Class) valid() bool {
	switch class {
	case ClassEvidence, ClassExport, ClassPolicy:
		return true
	default:
		return false
	}
}

func validProductID(value domain.ProductID) bool {
	if value.IsZero() {
		return false
	}
	parsed, err := domain.ParseProductID(value.String())
	return err == nil && parsed == value
}

func workspacePrefix(scope domain.Scope) string {
	return "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/"
}

func validBuiltValue(value, workspaceRoot string, trailingSlash bool) bool {
	if value == "" || len(value) > maximumKeyBytes || !utf8.ValidString(value) ||
		!strings.HasPrefix(value, workspaceRoot) || strings.HasSuffix(value, "/") != trailingSlash || strings.Contains(value, "//") {
		return false
	}
	trimmed := strings.TrimSuffix(value, "/")
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == "" || segment == "." || segment == ".." || !safeSegmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}
