package validator

type ValidatorClient interface {
	CheckPrerequisites() error
}
