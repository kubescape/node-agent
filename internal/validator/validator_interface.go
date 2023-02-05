package validator

type validatorClient interface {
	CheckPrerequsits() error
}
