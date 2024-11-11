package jawsauth

import "testing"

func Test_errtext(t *testing.T) {
	if errtext(ErrOAuth2WrongState) != ErrOAuth2WrongState.Error() {
		t.Fatal()
	}
}
