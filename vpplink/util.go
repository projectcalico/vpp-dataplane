package vpplink

var (
	strAddRemove     = map[bool]string{true: "add", false: "remove"}
	strSetUnset      = map[bool]string{true: "set", false: "unset"}
	strUpDown        = map[bool]string{true: "up", false: "down"}
	strEnableDisable = map[bool]string{true: "enable", false: "disable"}
	strIP46          = map[bool]string{true: "IP6", false: "IP4"}
)

func DefaultIntTo(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}

func isAddStr(isAdd bool) string {
	if isAdd {
		return "add"
	} else {
		return "delete"
	}
}
