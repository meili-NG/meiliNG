package types

// BlankStruct is an empty struct for blank responses
type BlankStruct struct{}

// BlankBody wraps BlankStruct for Huma responses
type BlankBody struct {
	Body BlankStruct
}
