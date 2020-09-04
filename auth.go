package htpasswd

import (
	"bufio"
	//"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/rclancey/fsutil"
	"github.com/rclancey/httpserver/auth"
	"golang.org/x/crypto/bcrypt"
)

type HTPasswd struct {
	filename string
}

func NewHTPasswd(filename string) *HTPasswd {
	return &HTPasswd{filename}
}

func (a *HTPasswd) GetUserByEmail(email string) (*auth.User, error) {
	var found *auth.User
	err := fsutil.ReadLocked(a.filename, func(f io.ReadSeeker) error {
		buf := bufio.NewReader(f)
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return errors.Wrapf(err, "can't read password file %s", a.filename)
			}
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 3 {
				vals, err := url.ParseQuery(parts[2])
				if err == nil && vals.Get("email") == email {
					found = &auth.User{
						Username: parts[0],
						ID: vals.Get("id"),
						FirstName: vals.Get("first_name"),
						LastName: vals.Get("last_name"),
						FullName: vals.Get("full_name"),
						Email: vals.Get("email"),
						Avatar: vals.Get("avatar"),
						Provider: "htpasswd",
					}
					return nil
				}
			}
		}
		found = nil
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "can't read password file %s", a.filename)
	}
	return found, nil
}

func (a *HTPasswd) CreateUser(user *auth.User, password string) error {
	var username string
	if user.Username != "" {
		username = user.Username
	} else if user.Email != "" {
		username = user.Email
	} else if user.ID != "" {
		username = user.ID
	} else {
		return errors.New("no username provided")
	}
	username = url.QueryEscape(username)
	cpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "can't encrypt password")
	}
	return fsutil.UpdateLocked(a.filename, func(rf io.ReadSeeker, wf io.Writer) error {
		buf := bufio.NewReader(rf)
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "can't read password file %s", a.filename)
			}
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 2 && parts[0] == username {
				return errors.Errorf("user %s already exists", username)
			}
			_, err = wf.Write([]byte(strings.TrimSpace(line) + "\n"))
			if err != nil {
				return errors.Wrapf(err, "error writing password file %s", a.filename)
			}
		}
		vals := url.Values{}
		if user.ID != "" {
			vals.Set("id", user.ID)
		}
		if user.FirstName != "" {
			vals.Set("first_name", user.FirstName)
		}
		if user.LastName != "" {
			vals.Set("last_name", user.LastName)
		}
		if user.FullName != "" {
			vals.Set("full_name", user.FullName)
		}
		if user.Email != "" {
			vals.Set("email", user.Email)
		}
		if user.Avatar != "" {
			vals.Set("avatar", user.Avatar)
		}
		parts := []string{
			username,
			string(cpw),
			vals.Encode(),
		}
		_, err = wf.Write([]byte(strings.Join(parts, ":") + "\n"))
		if err != nil {
			return errors.Wrapf(err, "error writing password file %s", a.filename)
		}
		return nil
	})
}

func (a *HTPasswd) UpdatePassword(username, password string) error {
	username = url.QueryEscape(username)
	cpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "can't encrypt password")
	}
	return fsutil.UpdateLocked(a.filename, func(rf io.ReadSeeker, wf io.Writer) error {
		buf := bufio.NewReader(rf)
		found := false
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					if found {
						return nil
					}
					return errors.Errorf("user %s does not exist", username)
				}
				return errors.Wrapf(err, "can't read password file %s", a.filename)
			}
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 2 && parts[0] == username {
				parts[1] = string(cpw)
				_, err = wf.Write([]byte(strings.Join(parts, ":") + "\n"))
				if err != nil {
					return errors.Wrapf(err, "error writing password file %s", a.filename)
				}
				found = true
			} else {
				_, err = wf.Write([]byte(strings.TrimSpace(line) + "\n"))
				if err != nil {
					return errors.Wrapf(err, "error writing password file %s", a.filename)
				}
			}
		}
		return nil
	})
}

func (a *HTPasswd) DeleteUser(username string) error {
	username = url.QueryEscape(username)
	return fsutil.UpdateLocked(a.filename, func(rf io.ReadSeeker, wf io.Writer) error {
		buf := bufio.NewReader(rf)
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return errors.Wrapf(err, "can't read password file %s", a.filename)
			}
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 2 && parts[0] == username {
				continue
			}
			_, err = wf.Write([]byte(strings.TrimSpace(line) + "\n"))
			if err != nil {
				return errors.Wrapf(err, "error writing password file %s", a.filename)
			}
		}
		return nil
	})
}

func (a *HTPasswd) Authenticate(username, password string) (*auth.User, error) {
	xusername := url.QueryEscape(username)
	var found *auth.User
	err := fsutil.ReadLocked(a.filename, func(f io.ReadSeeker) error {
		buf := bufio.NewReader(f)
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return errors.Wrapf(err, "can't read password file %s", a.filename)
			}
			parts := strings.Split(strings.TrimSpace(line), ":")
			if len(parts) >= 2 && parts[0] == xusername {
				err := bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte(password))
				if err == nil {
					found = &auth.User{Username: username}
					if len(parts) >= 3 {
						vals, err := url.ParseQuery(parts[2])
						if err == nil {
							found.ID = vals.Get("id")
							found.FirstName = vals.Get("first_name")
							found.LastName = vals.Get("last_name")
							found.FullName = vals.Get("full_name")
							found.Email = vals.Get("email")
							found.Avatar = vals.Get("avatar")
							found.Provider = "htpasswd"
						}
					}
					return nil
				}
				if err == bcrypt.ErrMismatchedHashAndPassword {
					log.Printf("bad password: '%s'\n", password)
					found = nil
					return nil
				}
				return errors.Wrap(err, "can't compare hashed passwords")
			}
		}
		found = nil
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "can't read password file %s", a.filename)
	}
	return found, nil
}
