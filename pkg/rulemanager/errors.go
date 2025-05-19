package rulemanager

import "fmt"

var ErrRuleShouldNotBeAlerted = fmt.Errorf("rule should not be alerted")
var NoProfileAvailable = fmt.Errorf("no profile available")
