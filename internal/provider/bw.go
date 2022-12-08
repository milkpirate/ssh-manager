package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/omegion/ssh-manager/internal"
)

const (
	// BitwardenFolderName where the keys will be placed.
	BitwardenFolderName = "ssh-agent"

	// BitwardenCommand base command for Bitwarden.
	BitwardenCommand = "bw"

	BitwardenFolderObjectType = "folder"
	// BitwardenFolderObjectTypePlural = "folders"

	BitwardenItemObjectType       = "item"
	BitwardenItemObjectTypePlural = "items"

	BitwardenItemTypeLogin = 1
	// BitwardenItemTypeSecureNote = 2
	// BitwardenItemTypeCard       = 3
	// BitwardenItemTypeIdentity   = 4

	errNoGetF      = "object %q with name %q not found in %q"
	errNoParseList = "cannot parse list"
	errNoParseGetF = "cannot parse output of get object %q with name %q"
)

// Bitwarden for connection.
type Bitwarden struct {
	Commander internal.Commander
	FolderID  *string
}

// BitwardenItemIn is the input struct to Bitwarden.
type BitwardenItemIn struct {
	ID       *string `json:"id"`
	Type     int     `json:"type"`
	Name     string  `json:"name"`
	Notes    string  `json:"notes"`
	Login    string  `json:"login"`
	FolderID *string `json:"folderId"`
}

// BitwardenItemOut is the output struct from Bitwarden.
type BitwardenItemOut struct {
	ID    *string `json:"id"`
	Name  string  `json:"name"`
	Notes string  `json:"notes"`
}

// Encode encodes the BitwardenItemIn to JSON and then base64.
func (i *BitwardenItemIn) Encode() string {
	// nolint:errchkjson
	itemBytes, _ := json.Marshal(i)

	return base64.StdEncoding.EncodeToString(itemBytes)
}

func DecodeItem(stdout []byte) (*Item, error) {
	var tmp BitwardenItemOut

	err := json.Unmarshal(stdout, &tmp)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get output")
	}

	decodedRawNotes, err := base64.StdEncoding.DecodeString(tmp.Notes)
	if err != nil {
		return nil, err
	}

	item := Item{
		ID:   *tmp.ID,
		Name: tmp.Name,
	}

	err = json.Unmarshal(decodedRawNotes, &item.Values)
	if err != nil {
		return nil, err
	}

	return &item, err
}

func DecodeItems(stdout []byte) ([]*Item, error) {
	outs, err := DecodeBitwardenOuts(stdout)
	if err != nil {
		return nil, err
	}

	items := make([]*Item, 0)

	for _, temp := range outs {
		item := &Item{
			ID:   *temp.ID,
			Name: temp.Name,
		}
		items = append(items, item)
	}

	return items, nil
}

func DecodeBitwardenOut(stdout []byte) (BitwardenItemOut, error) {
	var item BitwardenItemOut

	if err := json.Unmarshal(stdout, &item); err != nil {
		return BitwardenItemOut{}, errors.Wrap(err, errNoParseList)
	}

	return item, nil
}

func DecodeBitwardenOuts(stdout []byte) ([]BitwardenItemOut, error) {
	var items []BitwardenItemOut
	err := json.Unmarshal(stdout, &items)
	if err != nil {
		return nil, errors.Wrap(err, errNoParseList)
	}

	return items, nil
}

// GetName returns name of the provider.
func (b *Bitwarden) GetName() string {
	return BitwardenCommand
}

// Add adds given item to Bitwarden.
func (b *Bitwarden) Add(item *Item) error {
	_, err := b.Get(GetOptions{
		Name: item.Name,
	})

	if err == nil {
		return ItemAlreadyExistsError{Name: item.Name}
	}

	encodedValues, err := item.EncodeValues()
	if err != nil {
		return err
	}

	bwItem := BitwardenItemIn{
		ID:       nil,
		Type:     BitwardenItemTypeLogin,
		Name:     item.Name,
		Notes:    encodedValues,
		Login:    item.Name,
		FolderID: b.FolderID,
	}

	_, err = b.Bw("create", BitwardenItemObjectType, bwItem.Encode())

	return err
}

// Get gets Item from Bitwarden with given item name.
func (b *Bitwarden) Get(options GetOptions) (*Item, error) {
	err := b.Sync()
	if err != nil {
		return nil, err
	}

	output, err := b.Bw("list", BitwardenItemObjectTypePlural, "--folderid", *b.FolderID)
	if err != nil {
		return nil, err
	}

	items, err := DecodeItems(output)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if item.Name == options.Name {
			return item, nil
		}
	}

	return nil, errors.Errorf(errNoGetF, BitwardenItemObjectType, options.Name, BitwardenFolderName)
}

// List lists all added SSH keys.
func (b *Bitwarden) List(options ListOptions) ([]*Item, error) {
	err := b.Sync()
	if err != nil {
		return nil, err
	}

	output, err := b.Bw("list", BitwardenItemObjectType, "--folderid", *b.FolderID)
	if err != nil {
		return nil, err
	}

	return DecodeItems(output)
}

// Sync syncs Bitwarden vault.
func (b *Bitwarden) Sync() error {
	_, err := b.Bw("sync")
	if err != nil {
		return err
	}

	log.Debugln("Syncing Bitwarden Vault.")

	b.FolderID, err = b.EnsureFolder(BitwardenFolderName)
	if err != nil {
		return err
	}

	return nil
}

func (b *Bitwarden) EnsureFolder(name string) (*string, error) {
	folderUUID, err := b.GetFolder(name)
	if err == nil {
		log.Debugln("Folder already exists.")

		return folderUUID, nil
	}

	log.Debugf("Folder %q must be created.", name)

	bwItem := BitwardenItemIn{
		Name: name,
	}
	output, err := b.Bw("create", BitwardenFolderObjectType, bwItem.Encode())
	if err != nil {
		return nil, err
	}

	log.Debugf("Created %q folder.", name)

	out, err := DecodeBitwardenOut(output)
	if err != nil {
		return nil, errors.Wrapf(err, errNoParseGetF, BitwardenFolderObjectType, BitwardenFolderName)
	}

	return out.ID, err
}

func (b *Bitwarden) Bw(args ...string) ([]byte, error) {
	command := b.Commander.Executor.CommandContext(
		context.Background(),
		BitwardenCommand,
		args...,
	)

	var stderr bytes.Buffer

	command.SetStderr(&stderr)

	stdout, err := command.Output()
	if err != nil {
		args = append([]string{BitwardenCommand}, args...)

		return stdout, ExecutionFailedError{
			Command: strings.Join(args, " "),
			Message: fmt.Sprintf("%v: %s", err, stderr.String()),
		}
	}

	return stdout, nil
}

func (b *Bitwarden) GetFolder(name string) (*string, error) {
	output, err := b.Bw("get", BitwardenFolderObjectType, name)
	if err != nil {
		return nil, errors.Wrapf(err, errNoParseGetF, BitwardenFolderObjectType, name)
	}

	out, err := DecodeBitwardenOut(output)
	if err != nil {
		return nil, errors.Wrapf(err, errNoParseGetF, BitwardenFolderObjectType, BitwardenFolderName)
	}

	return out.ID, err
}
