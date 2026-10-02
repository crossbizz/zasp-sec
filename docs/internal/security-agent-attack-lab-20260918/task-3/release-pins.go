package main

import (
 "fmt"
 "github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func main() {
 if migrations.ProductionCompliance().Checksum()!="f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1" || migrations.ComplianceFingerprint()!="8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced" { panic("accepted56 changed") }
 if migrations.ProductionSecurityAgentExistingTests().Checksum()!="01920b296d2ebbc4b84c6e714edaf50d6265d630e577bd26297755a15289fa00" || migrations.SecurityAgentExistingTestsFingerprint()!="2c324e78917f97feee14f915b397efbb92a183d47afd7473139dd0691cf0bb04" { panic("accepted55 changed") }
 fmt.Printf("release57 checksum=%s fingerprint=%s\n",migrations.ProductionSecurityAgentAttackLab().Checksum(),migrations.SecurityAgentAttackLabFingerprint())
 fmt.Printf("release56 checksum=%s fingerprint=%s\n",migrations.ProductionCompliance().Checksum(),migrations.ComplianceFingerprint())
 fmt.Printf("release55 checksum=%s fingerprint=%s\n",migrations.ProductionSecurityAgentExistingTests().Checksum(),migrations.SecurityAgentExistingTestsFingerprint())
}
