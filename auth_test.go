package htpasswd

import (
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/rclancey/httpserver/auth"

	. "gopkg.in/check.v1"
)

func tempFile(ext string) string {
	var randBytes = make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), hex.EncodeToString(randBytes) + ext)
}

func Test(t *testing.T) { TestingT(t) }
type AuthSuite struct {}

var _ = Suite(&AuthSuite{})

func (s *AuthSuite) TestCreateUser(c *C) {
	fn := tempFile(".htpasswd")
	c.Log(fn)
	defer os.Remove(fn)
	htp := NewHTPasswd(fn)
	err := htp.CreateUser(&auth.User{Username: "john@beatles.com"}, "yellow submarine")
	c.Check(err, IsNil)
	err = htp.CreateUser(&auth.User{Email: "john@beatles.com"}, "yellow submarine")
	c.Check(err, ErrorMatches, "^.*user .* already exists.*$")
	err = htp.CreateUser(&auth.User{ID: "john@beatles.com"}, "yellow submarine")
	c.Check(err, ErrorMatches, "^.*user .* already exists.*$")
	err = htp.CreateUser(&auth.User{FullName: "john lennon"}, "yellow submarine")
	c.Check(err, ErrorMatches, "^.*no username provided.*$")
	user, err := htp.Authenticate("john@beatles.com", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	c.Check(user.Username, Equals, "john@beatles.com")
}

func (s *AuthSuite) TestUpdatePassword(c *C) {
	fn := tempFile(".htpasswd")
	defer os.Remove(fn)
	htp := NewHTPasswd(fn)
	err := htp.CreateUser(&auth.User{Email: "john@beatles.com"}, "yellow submarine")
	c.Check(err, IsNil)
	err = htp.UpdatePassword("john@beatles.com", "i am the walrus")
	c.Check(err, IsNil)
	err = htp.UpdatePassword("paul@beatles.com", "koo koo ka choo")
	c.Check(err, ErrorMatches, "^.*user .* does not exist.*$")
	user, err := htp.Authenticate("john@beatles.com", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, IsNil)
	user, err = htp.Authenticate("john@beatles.com", "i am the walrus")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	c.Check(user.Username, Equals, "john@beatles.com")
}

func (s *AuthSuite) TestDeleteUser(c *C) {
	fn := tempFile(".htpasswd")
	defer os.Remove(fn)
	htp := NewHTPasswd(fn)
	err := htp.CreateUser(&auth.User{Email: "john@beatles.com"}, "yellow submarine")
	c.Check(err, IsNil)
	err = htp.CreateUser(&auth.User{Email: "paul@beatles.com"}, "i am the egg man")
	user, err := htp.Authenticate("john@beatles.com", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	user, err = htp.Authenticate("paul@beatles.com", "i am the egg man")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	err = htp.DeleteUser("john@beatles.com")
	c.Check(err, IsNil)
	err = htp.DeleteUser("ringo@beatles.com")
	c.Check(err, IsNil)
	user, err = htp.Authenticate("john@beatles.com", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, IsNil)
	user, err = htp.Authenticate("paul@beatles.com", "i am the egg man")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
}

func (s *AuthSuite) TestAuthenticate(c *C) {
	fn := tempFile(".htpasswd")
	defer os.Remove(fn)
	htp := NewHTPasswd(fn)
	err := htp.CreateUser(&auth.User{
		ID: "12345678-90ab-cdef-1234-567890abcdef",
		Username: "jlennon",
		FirstName: "John",
		LastName: "Lennon",
		Email: "john@beatles.com",
	}, "yellow submarine")
	c.Check(err, IsNil)
	err = htp.CreateUser(&auth.User{
		Email: "paul@beatles.com",
		FullName: "Paul McCartney",
	}, "i am the walrus")
	c.Check(err, IsNil)
	user, err := htp.Authenticate("john@beatles.com", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, IsNil)
	user, err = htp.Authenticate("jlennon", "i am the walrus")
	c.Check(err, IsNil)
	c.Check(user, IsNil)
	user, err = htp.Authenticate("jlennon", "yellow submarine")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	c.Check(user.ID, Equals, "12345678-90ab-cdef-1234-567890abcdef")
	c.Check(user.Username, Equals, "jlennon")
	c.Check(user.FirstName, Equals, "John")
	c.Check(user.LastName, Equals, "Lennon")
	c.Check(user.FullName, Equals, "")
	c.Check(user.Email, Equals, "john@beatles.com")
	c.Check(user.Avatar, Equals, "")
	user, err = htp.Authenticate("paul@beatles.com", "i am the walrus")
	c.Check(err, IsNil)
	c.Check(user, NotNil)
	c.Check(user.ID, Equals, "")
	c.Check(user.Username, Equals, "paul@beatles.com")
	c.Check(user.FirstName, Equals, "")
	c.Check(user.LastName, Equals, "")
	c.Check(user.FullName, Equals, "Paul McCartney")
	c.Check(user.Email, Equals, "paul@beatles.com")
	c.Check(user.Avatar, Equals, "")
}
