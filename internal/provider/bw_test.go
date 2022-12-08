package provider_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/omegion/ssh-manager/internal"
	"github.com/omegion/ssh-manager/internal/provider"
	"github.com/omegion/ssh-manager/test"
)

func ptr(s string) *string {
	return &s
}

func TestBitwarden_Add(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list items --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  []byte("[]"),
		},
		{
			//nolint:lll // allow long lines.
			Command: "bw create item eyJpZCI6bnVsbCwidHlwZSI6MSwibmFtZSI6InRlc3QiLCJub3RlcyI6Ilczc2libUZ0WlNJNkluQnlhWFpoZEdWZmEyVjVJaXdpZG1Gc2RXVWlPaUpZSW4wc2V5SnVZVzFsSWpvaWNIVmliR2xqWDJ0bGVTSXNJblpoYkhWbElqb2lXU0o5WFE9PSIsImxvZ2luIjoidGVzdCIsImZvbGRlcklkIjoiOTExMGM2NTEtN2IzNy00YmVhLTg1ODAtYWY2NDAxM2E5YTkyIn0=",
			StdOut:  test.Must(test.LoadFixture("bw_add.json")),
		},
	}

	bitw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	item := provider.Item{
		Name: "test",
		Values: []provider.Field{
			{
				Name:  "private_key",
				Value: "X",
			},
			{
				Name:  "public_key",
				Value: "Y",
			},
		},
	}

	err := bitw.Add(&item)

	assert.NoError(t, err)
}

func TestBitwarden_Add_ItemExists(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list items --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  test.Must(test.LoadFixture("bw_list.json")),
		},
		{
			//nolint:lll // allow long lines.
			Command: "bw create item eyJpZCI6bnVsbCwidHlwZSI6MSwibmFtZSI6InRlc3QiLCJub3RlcyI6ImJuVnNiQT09IiwibG9naW4iOiJ0ZXN0IiwiZm9sZGVySWQiOiI5MTEwYzY1MS03YjM3LTRiZWEtODU4MC1hZjY0MDEzYTlhOTIifQ==",
			StdOut:  test.Must(test.LoadFixture("bw_add.json")),
		},
	}

	bitw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	item := provider.Item{
		Name: "test1",
	}

	err := bitw.Add(&item)

	assert.EqualError(t, err, "item test1 already exists")
}

func TestBitwarden_Get_Erro(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list items --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  test.Must(test.LoadFixture("bw_get_not_found.txt")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	item, err := bw.Get(provider.GetOptions{Name: "test2"})

	assert.Equal(t, (*provider.Item)(nil), item)
	assert.EqualError(t, err, "cannot parse list: invalid character 'N' looking for beginning of value")
}

func TestBitwarden_Get_NothingFound(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list items --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  []byte("[]"),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	item, err := bw.Get(provider.GetOptions{Name: "test2"})

	assert.Equal(t, (*provider.Item)(nil), item)
	assert.EqualError(t, err, "object \"item\" with name \"test2\" not found in \"ssh-agent\"")
}

func TestBitwarden_Get(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list items --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  test.Must(test.LoadFixture("bw_list.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	item, err := bw.Get(provider.GetOptions{Name: "test2"})

	assert.NoError(t, err)
	assert.Equal(t, "test2", item.Name)
}

func TestBitwarden_GetNotFound(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
			StdErr:  []byte("some err"),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	err := bw.Sync()

	assert.EqualError(t, err, "'bw sync': Execution failed: some err: ")
}

func TestBitwarden_Sync(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	err := bw.Sync()

	assert.NoError(t, err)
}

func TestBitwarden_List(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw sync",
		},
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, provider.BitwardenFolderName),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
		{
			Command: "bw list item --folderid 9110c651-7b37-4bea-8580-af64013a9a92",
			StdOut:  test.Must(test.LoadFixture("bw_list.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	items, err := bw.List(provider.ListOptions{})

	expectedItems := []string{
		"test1",
		"test2",
	}

	assert.NoError(t, err)

	for idx, item := range items {
		assert.Equal(t, expectedItems[idx], item.Name)
	}
}

func TestBitwarden_DecodeBitwardenOuts(t *testing.T) {
	in := test.Must(test.LoadFixture("bw_list.json"))
	out, err := provider.DecodeBitwardenOuts(in)

	assert.Nil(t, err)
	assert.Equal(t, []provider.BitwardenItemOut{
		{
			ID:    ptr("6fe3bf5f-d418-4bc1-b34d-ad2f011a31e2"),
			Name:  "test1",
			Notes: "W3sibmFtZSI6InByaXZhdGVfa2V5IiwidmFsdWUiOiJYIn0seyJuYW1lIjoicHVibGljX2tleSIsInZhbHVlIjoiWSJ9XQ==",
		},
		{
			ID:    ptr("6fe3bf5f-d418-4bc1-b34d-ad2f011a31e2"),
			Name:  "test2",
			Notes: "W3sibmFtZSI6InByaXZhdGVfa2V5IiwidmFsdWUiOiJYIn0seyJuYW1lIjoicHVibGljX2tleSIsInZhbHVlIjoiWSJ9XQ==",
		},
	}, out)
}

func TestBitwarden_DecodeItem(t *testing.T) {
	in := test.Must(test.LoadFixture("bw_get.json"))
	out, err := provider.DecodeItem(in)

	assert.Nil(t, err)
	assert.Equal(t, &provider.Item{
		ID:   "6fe3bf5f-d418-4bc1-b34d-ad2f011a31e2",
		Name: "test",
		Values: []provider.Field{
			{
				Name:  "private_key",
				Value: "X",
			},
			{
				Name:  "public_key",
				Value: "Y",
			},
		},
	}, out)
}

func TestBitwarden_DecodeItems_Err(t *testing.T) {
	in := test.Must(test.LoadFixture("bw_get_not_found.txt"))
	out, err := provider.DecodeItems(in)

	assert.Equal(t, []*provider.Item(nil), out)
	assert.EqualError(t, err, "cannot parse list: invalid character 'N' looking for beginning of value")
}

func TestBitwarden_DecodeItems(t *testing.T) {
	in := test.Must(test.LoadFixture("bw_list.json"))
	out, err := provider.DecodeItems(in)

	assert.Nil(t, err)
	assert.Equal(t, []*provider.Item{
		{
			ID:     "6fe3bf5f-d418-4bc1-b34d-ad2f011a31e2",
			Name:   "test1",
			Values: nil,
			Bucket: nil,
		},
		{
			ID:     "6fe3bf5f-d418-4bc1-b34d-ad2f011a31e2",
			Name:   "test2",
			Values: nil,
			Bucket: nil,
		},
	}, out)
}

func TestBitwarden_EnsureFolder_NotExistsErr(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, "fooFolder"),
			StdOut:  test.Must(test.LoadFixture("bw_get_not_found.txt")),
		},
		{
			//nolint:lll // allow long lines.
			Command: fmt.Sprintf("bw create %s %s", provider.BitwardenFolderObjectType, "eyJpZCI6bnVsbCwidHlwZSI6MCwibmFtZSI6ImZvb0ZvbGRlciIsIm5vdGVzIjoiIiwibG9naW4iOiIiLCJmb2xkZXJJZCI6bnVsbH0="),
			StdErr:  []byte("some err"),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actualUUID, err := bw.EnsureFolder("fooFolder")

	assert.Equal(t, (*string)(nil), actualUUID)
	//nolint:lll // allow long lines.
	assert.EqualError(t, err, "'bw create folder eyJpZCI6bnVsbCwidHlwZSI6MCwibmFtZSI6ImZvb0ZvbGRlciIsIm5vdGVzIjoiIiwibG9naW4iOiIiLCJmb2xkZXJJZCI6bnVsbH0=': Execution failed: some err: ")
}

func TestBitwarden_EnsureFolder_NotExists(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, "fooFolder"),
			StdOut:  test.Must(test.LoadFixture("bw_get_not_found.txt")),
		},
		{
			//nolint:lll // allow long lines.
			Command: fmt.Sprintf("bw create %s %s", provider.BitwardenFolderObjectType, "eyJpZCI6bnVsbCwidHlwZSI6MCwibmFtZSI6ImZvb0ZvbGRlciIsIm5vdGVzIjoiIiwibG9naW4iOiIiLCJmb2xkZXJJZCI6bnVsbH0="),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actualUUID, err := bw.EnsureFolder("fooFolder")

	assert.Equal(t, ptr("9110c651-7b37-4bea-8580-af64013a9a92"), actualUUID)
	assert.Nil(t, err)
}

func TestBitwarden_EnsureFolder_Exists(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, "fooFolder"),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actualUUID, err := bw.EnsureFolder("fooFolder")

	assert.Equal(t, ptr("9110c651-7b37-4bea-8580-af64013a9a92"), actualUUID)
	assert.Nil(t, err)
}

func TestBitwarden_Bw_Bad(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: "bw foo bar",
			StdOut:  []byte("stdout"),
			StdErr:  []byte("stderr"),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actlStdout, err := bw.Bw("foo", "bar")

	assert.Equal(t, []byte("stdout"), actlStdout)
	assert.EqualError(t, err, "'bw foo bar': Execution failed: stderr: ")
}

func TestBitwarden_Bw_Good(t *testing.T) {
	expStdout := test.Must(test.LoadFixture("bw_ok.json"))

	expectedCommands := []test.FakeCommand{
		{
			Command: "bw foo bar",
			StdOut:  expStdout,
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actlStdout, err := bw.Bw("foo", "bar")

	assert.NoError(t, err)
	assert.Equal(t, expStdout, actlStdout)
}

func TestBitwarden_GetFolder(t *testing.T) {
	expectedCommands := []test.FakeCommand{
		{
			Command: fmt.Sprintf("bw get %s %s", provider.BitwardenFolderObjectType, "fooFolder"),
			StdOut:  test.Must(test.LoadFixture("bw_get_folder.json")),
		},
	}

	bw := provider.Bitwarden{
		Commander: internal.Commander{Executor: test.NewExecutor(expectedCommands)},
	}

	actualUUID, err := bw.GetFolder("fooFolder")

	assert.NoError(t, err)
	assert.Equal(t, ptr("9110c651-7b37-4bea-8580-af64013a9a92"), actualUUID)
}
