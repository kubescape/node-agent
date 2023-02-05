package validator

type ValidatorClient interface {
	CheckPrerequsits() error
}
