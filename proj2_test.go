package proj2

// Você NÃO PODE alterar o que é importado. Se você adicionar QUALQUER
// importação adicional, o corretor automático quebrará.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/RafaelTupynamba/Projeto2/userlib"
	_ "github.com/google/uuid"
)


func TestInit(t *testing.T) {
        t.Log("Teste de inicialização")

        // Talvez você queira desativar isso em algum momento
        userlib.SetDebugStatus(true)
        // someUsefulThings()  //  Não chame someUsefulThings() no corretor automático, caso um aluno a remova
        userlib.SetDebugStatus(false)
        u, err := InitUser("alice", "fubar")
        if err != nil {
                // t.Error indica que o teste falhou
                t.Error("Falha ao inicializar usuário", err)
                return
        }
        // t.Log() apenas produz saída se você executar com "go test -v"
        t.Log("Usuário obtido", u)
        // Se você quiser comentar a linha acima,
        // escreva _ = u aqui para satisfazer o compilador
        // Provavelmente você quer muitos testes a mais aqui.
}


func TestStorage(t *testing.T) {
        // E alguns testes a mais, porque
        u, err := GetUser("alice", "fubar")
        if err != nil {
                t.Error("Falha ao recarregar usuário", err)
                return
        }
        t.Log("Usuário carregado", u)

        v := []byte("This is a test")
        u.StoreFile("file1", v)


        v2, err2 := u.LoadFile("file1")
        if err2 != nil {
                t.Error("Falha ao enviar e baixar", err2)
                return
        }
        if !reflect.DeepEqual(v, v2) {
                t.Error("O arquivo baixado não é o mesmo", v, v2)
                return
        }
}

func TestShare(t *testing.T) {
        u, err := GetUser("alice", "fubar")
        if err != nil {
                t.Error("Falha ao recarregar usuário", err)
                return
        }
        u2, err2 := InitUser("bob", "foobar")
        if err2 != nil {
                t.Error("Falha ao inicializar bob", err2)
                return
        }

        var v, v2 []byte
        var magic_string string

        v, err = u.LoadFile("file1")
        if err != nil {
                t.Error("Falha ao baixar o arquivo de alice", err)
                return
        }

        magic_string, err = u.ShareFile("file1", "bob")
        if err != nil {
                t.Error("Falha ao compartilhar um arquivo", err)
                return
        }
        err = u2.ReceiveFile("file2", "alice", magic_string)
        if err != nil {
                t.Error("Falha ao receber a mensagem de compartilhamento", err)
                return
        }

        v2, err = u2.LoadFile("file2")
        if err != nil {
                t.Error("Falha ao baixar o arquivo após o compartilhamento", err)
                return
        }
        if !reflect.DeepEqual(v, v2) {
                t.Error("O arquivo compartilhado não é o mesmo", v, v2)
                return
        }

}

// TESTES ADICIONAIS 

func reset() {
        userlib.DatastoreClear()
        userlib.KeystoreClear()
}

// initOrFail cria um usuário e interrompe o teste em caso de erro.
func initOrFail(t *testing.T, username string, password string) *User {
        u, err := InitUser(username, password)
        if err != nil || u == nil {
                t.Fatal("Falha ao inicializar", username, err)
        }
        return u
}

// expectContent verifica que o arquivo existe e tem o conteúdo esperado.
func expectContent(t *testing.T, u *User, filename string, want []byte) {
        got, err := u.LoadFile(filename)
        if err != nil {
                t.Fatal("LoadFile falhou", filename, err)
        }
        if !reflect.DeepEqual(got, want) {
                t.Fatal("Conteúdo diferente do esperado", filename, string(got), string(want))
        }
}

// expectNoAccess verifica que o usuário NÃO obtém o conteúdo secret:
// ou ocorre um erro, ou o valor retornado é diferente.
func expectNoAccess(t *testing.T, u *User, filename string, secret []byte) {
        got, err := u.LoadFile(filename)
        if err == nil && reflect.DeepEqual(got, secret) {
                t.Fatal("Usuário obteve conteúdo ao qual não deveria ter acesso", filename)
        }
}

// snapshotKeys guarda as chaves atuais do datastore.
func snapshotKeys() map[userlib.UUID]bool {
        keys := make(map[userlib.UUID]bool)
        for k := range userlib.DatastoreGetMap() {
                keys[k] = true
        }
        return keys
}

// newKeys retorna as chaves criadas depois do snapshot.
func newKeys(before map[userlib.UUID]bool) []userlib.UUID {
        var out []userlib.UUID
        for k := range userlib.DatastoreGetMap() {
                if !before[k] {
                        out = append(out, k)
                }
        }
        return out
}

func TestUserErrors(t *testing.T) {
        reset()
        initOrFail(t, "alice", "senha-forte-alice")

        if _, err := InitUser("alice", "outra-senha"); err == nil {
                t.Error("InitUser deveria falhar para usuário existente")
        }
        if _, err := GetUser("alice", "senha-errada"); err == nil {
                t.Error("GetUser deveria falhar com senha errada")
        }
        if _, err := GetUser("naoexiste", "senha-forte-alice"); err == nil {
                t.Error("GetUser deveria falhar para usuário inexistente")
        }
        if _, err := GetUser("alice", "senha-forte-alice"); err != nil {
                t.Error("GetUser falhou com credenciais corretas", err)
        }

        // Mesma senha para usuários diferentes é permitido.
        initOrFail(t, "bob", "senha-forte-alice")
        if _, err := GetUser("bob", "senha-forte-alice"); err != nil {
                t.Error("GetUser falhou para bob", err)
        }
}

func TestUsernameNotInDatastore(t *testing.T) {
        reset()
        initOrFail(t, "usernamesecreto", "senha")
        for _, v := range userlib.DatastoreGetMap() {
                if reflect.DeepEqual(v, []byte("usernamesecreto")) {
                        t.Error("Nome de usuário armazenado em claro")
                }
                for i := 0; i+len("usernamesecreto") <= len(v); i++ {
                        if string(v[i:i+len("usernamesecreto")]) == "usernamesecreto" {
                                t.Fatal("Nome de usuário aparece em claro no datastore")
                        }
                }
        }
}

func TestUserTampering(t *testing.T) {
        reset()
        initOrFail(t, "alice", "senha")
        for k, v := range userlib.DatastoreGetMap() {
                corrupted := make([]byte, len(v))
                copy(corrupted, v)
                corrupted[len(corrupted)/2] ^= 0xff
                userlib.DatastoreSet(k, corrupted)
        }
        if _, err := GetUser("alice", "senha"); err == nil {
                t.Error("GetUser deveria detectar dados corrompidos")
        }

        reset()
        initOrFail(t, "alice", "senha")
        for k := range userlib.DatastoreGetMap() {
                userlib.DatastoreSet(k, []byte("lixo"))
        }
        if _, err := GetUser("alice", "senha"); err == nil {
                t.Error("GetUser deveria detectar dados truncados")
        }

        reset()
        initOrFail(t, "alice", "senha")
        userlib.DatastoreClear()
        if _, err := GetUser("alice", "senha"); err == nil {
                t.Error("GetUser deveria falhar se os dados foram apagados")
        }
}

func TestMultipleInstances(t *testing.T) {
        reset()
        a1 := initOrFail(t, "alice", "senha")
        a2, err := GetUser("alice", "senha")
        if err != nil {
                t.Fatal(err)
        }
        a1.StoreFile("f", []byte("um"))
        expectContent(t, a2, "f", []byte("um"))
        if err = a2.AppendFile("f", []byte("dois")); err != nil {
                t.Fatal(err)
        }
        expectContent(t, a1, "f", []byte("umdois"))
        a2.StoreFile("f", []byte("tres"))
        expectContent(t, a1, "f", []byte("tres"))
}

func TestStoreLoadAppend(t *testing.T) {
        reset()
        u := initOrFail(t, "alice", "senha")

        // Arquivo inexistente: nil, sem erro.
        data, err := u.LoadFile("inexistente")
        if err != nil || data != nil {
                t.Error("LoadFile de arquivo inexistente deveria retornar nil, nil", data, err)
        }
        if err = u.AppendFile("inexistente", []byte("x")); err == nil {
                t.Error("AppendFile deveria falhar para arquivo inexistente")
        }

        // Tamanhos variados (inclusive múltiplos do bloco AES).
        sizes := []int{1, 15, 16, 17, 32, 1000}
        for _, n := range sizes {
                v := userlib.RandomBytes(n)
                u.StoreFile("arq", v)
                expectContent(t, u, "arq", v)
        }

        u.StoreFile("arq", []byte("abc"))
        expected := []byte("abc")
        for i := 0; i < 10; i++ {
                part := userlib.RandomBytes(i * 7 + 1)
                if err = u.AppendFile("arq", part); err != nil {
                        t.Fatal("AppendFile falhou", err)
                }
                expected = append(expected, part...)
        }
        expectContent(t, u, "arq", expected)

        // Sobrescrever após appends.
        u.StoreFile("arq", []byte("novo"))
        expectContent(t, u, "arq", []byte("novo"))

        // Funciona após "reiniciar" o cliente.
        u2, err := GetUser("alice", "senha")
        if err != nil {
                t.Fatal(err)
        }
        expectContent(t, u2, "arq", []byte("novo"))
}

func TestSameFilenameDifferentUsers(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha")
        b := initOrFail(t, "bob", "senha")
        a.StoreFile("f", []byte("alice"))
        b.StoreFile("f", []byte("bob"))
        expectContent(t, a, "f", []byte("alice"))
        expectContent(t, b, "f", []byte("bob"))
}

func TestFileContentNotInDatastore(t *testing.T) {
        reset()
        u := initOrFail(t, "alice", "senha")
        secret := "conteudosupersecreto"
        u.StoreFile("nomesecreto", []byte(secret))
        u.AppendFile("nomesecreto", []byte(secret))
        for _, v := range userlib.DatastoreGetMap() {
                s := string(v)
                for _, w := range []string{secret, "nomesecreto"} {
                        for i := 0; i+len(w) <= len(s); i++ {
                                if s[i:i+len(w)] == w {
                                        t.Fatal("Dado em claro no datastore", w)
                                }
                        }
                }
        }
}

func TestFileTampering(t *testing.T) {
        reset()
        u := initOrFail(t, "alice", "senha")
        before := snapshotKeys()
        u.StoreFile("f", []byte("conteudo original"))
        u.AppendFile("f", []byte(" mais"))
        created := newKeys(before)
        if len(created) == 0 {
                t.Fatal("StoreFile não gravou nada no datastore")
        }
        ds := userlib.DatastoreGetMap()
        for _, k := range created {
                v := ds[k]
                corrupted := make([]byte, len(v))
                copy(corrupted, v)
                corrupted[0] ^= 0x01
                corrupted[len(corrupted)-1] ^= 0x01
                userlib.DatastoreSet(k, corrupted)
        }
        data, err := u.LoadFile("f")
        if err == nil && data != nil {
                t.Error("LoadFile retornou dados apesar de corrupção", string(data))
        }
}

func TestFileTamperingEachRecord(t *testing.T) {
        // Corrompe um registro por vez: LoadFile nunca pode retornar um
        // valor incorreto.
        reset()
        u := initOrFail(t, "alice", "senha")
        before := snapshotKeys()
        u.StoreFile("f", []byte("parte1"))
        u.AppendFile("f", []byte("parte2"))
        created := newKeys(before)
        valid := []byte("parte1parte2")
        for _, k := range created {
                ds := userlib.DatastoreGetMap()
                original := ds[k]
                userlib.DatastoreSet(k, append(append([]byte{}, original...), 0x00))
                data, err := u.LoadFile("f")
                if err == nil && data != nil && !reflect.DeepEqual(data, valid) {
                        t.Error("LoadFile retornou valor incorreto", string(data))
                }
                userlib.DatastoreDelete(k)
                data, err = u.LoadFile("f")
                if err == nil && data != nil && !reflect.DeepEqual(data, valid) {
                        t.Error("LoadFile retornou valor incorreto após remoção", string(data))
                }
                userlib.DatastoreSet(k, original)
        }
        expectContent(t, u, "f", valid)
}

func TestSwapRecords(t *testing.T) {
        // Troca o conteúdo de dois arquivos diferentes no datastore.
        reset()
        u := initOrFail(t, "alice", "senha")
        before := snapshotKeys()
        u.StoreFile("a", []byte("arquivo A"))
        keysA := newKeys(before)
        before = snapshotKeys()
        u.StoreFile("b", []byte("arquivo B"))
        keysB := newKeys(before)
        ds := userlib.DatastoreGetMap()
        for i := 0; i < len(keysA) && i < len(keysB); i++ {
                ds[keysA[i]], ds[keysB[i]] = ds[keysB[i]], ds[keysA[i]]
        }
        dataA, errA := u.LoadFile("a")
        if errA == nil && reflect.DeepEqual(dataA, []byte("arquivo B")) {
                t.Error("Troca de registros não detectada")
        }
        dataB, errB := u.LoadFile("b")
        if errB == nil && reflect.DeepEqual(dataB, []byte("arquivo A")) {
                t.Error("Troca de registros não detectada")
        }
}

func TestShareTransitive(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        b := initOrFail(t, "bob", "senha-b")
        c := initOrFail(t, "carol", "senha-c")

        a.StoreFile("fa", []byte("v1"))
        msg, err := a.ShareFile("fa", "bob")
        if err != nil {
                t.Fatal(err)
        }
        if err = b.ReceiveFile("fb", "alice", msg); err != nil {
                t.Fatal(err)
        }
        msg, err = b.ShareFile("fb", "carol")
        if err != nil {
                t.Fatal(err)
        }
        if err = c.ReceiveFile("fc", "bob", msg); err != nil {
                t.Fatal(err)
        }
        expectContent(t, c, "fc", []byte("v1"))

        // Atualizações de qualquer um são vistas por todos.
        if err = c.AppendFile("fc", []byte("+carol")); err != nil {
                t.Fatal(err)
        }
        expectContent(t, a, "fa", []byte("v1+carol"))
        expectContent(t, b, "fb", []byte("v1+carol"))

        b.StoreFile("fb", []byte("sobrescrito por bob"))
        expectContent(t, a, "fa", []byte("sobrescrito por bob"))
        expectContent(t, c, "fc", []byte("sobrescrito por bob"))

        a.AppendFile("fa", []byte("!"))
        expectContent(t, c, "fc", []byte("sobrescrito por bob!"))

        // Funciona após reiniciar o cliente.
        c2, err := GetUser("carol", "senha-c")
        if err != nil {
                t.Fatal(err)
        }
        expectContent(t, c2, "fc", []byte("sobrescrito por bob!"))
}

func TestShareErrors(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        b := initOrFail(t, "bob", "senha-b")
        c := initOrFail(t, "carol", "senha-c")
        a.StoreFile("f", []byte("segredo"))

        if _, err := a.ShareFile("naoexiste", "bob"); err == nil {
                t.Error("ShareFile deveria falhar para arquivo inexistente")
        }
        if _, err := a.ShareFile("f", "ninguem"); err == nil {
                t.Error("ShareFile deveria falhar para destinatário inexistente")
        }

        msg, err := a.ShareFile("f", "bob")
        if err != nil {
                t.Fatal(err)
        }

        // Remetente errado.
        if err = b.ReceiveFile("g", "carol", msg); err == nil {
                t.Error("ReceiveFile aceitou mensagem com remetente errado")
        }
        // Destinatário errado.
        if err = c.ReceiveFile("g", "alice", msg); err == nil {
                expectNoAccess(t, c, "g", []byte("segredo"))
        }
        // Mensagem adulterada em cada posição (amostragem).
        for i := 0; i < len(msg); i += len(msg)/20 + 1 {
                tampered := []byte(msg)
                if tampered[i] == 'a' {
                        tampered[i] = 'b'
                } else {
                        tampered[i] = 'a'
                }
                if err = b.ReceiveFile("adulterado", "alice", string(tampered)); err == nil {
                        data, lerr := b.LoadFile("adulterado")
                        if lerr == nil && data != nil && !reflect.DeepEqual(data, []byte("segredo")) {
                                t.Error("Mensagem adulterada levou a conteúdo incorreto")
                        }
                }
        }
        if err = b.ReceiveFile("lixo", "alice", "nao eh uma mensagem"); err == nil {
                t.Error("ReceiveFile aceitou lixo")
        }
        if err = b.ReceiveFile("vazio", "alice", ""); err == nil {
                t.Error("ReceiveFile aceitou mensagem vazia")
        }

        // Mensagem correta continua funcionando.
        if err = b.ReceiveFile("ok", "alice", msg); err != nil {
                t.Fatal(err)
        }
        expectContent(t, b, "ok", []byte("segredo"))
}

func TestShareDoesNotLeakFilename(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        initOrFail(t, "bob", "senha-b")
        a.StoreFile("nomeprivadodealice", []byte("x"))
        msg, err := a.ShareFile("nomeprivadodealice", "bob")
        if err != nil {
                t.Fatal(err)
        }
        for i := 0; i+len("nomeprivadodealice") <= len(msg); i++ {
                if msg[i:i+len("nomeprivadodealice")] == "nomeprivadodealice" {
                        t.Fatal("Nome do arquivo aparece na mensagem")
                }
        }
}

func TestRevoke(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        b := initOrFail(t, "bob", "senha-b")
        c := initOrFail(t, "carol", "senha-c")

        a.StoreFile("f", []byte("antes"))
        msgB, err := a.ShareFile("f", "bob")
        if err != nil {
                t.Fatal(err)
        }
        if err = b.ReceiveFile("fb", "alice", msgB); err != nil {
                t.Fatal(err)
        }
        msgC, err := b.ShareFile("fb", "carol")
        if err != nil {
                t.Fatal(err)
        }
        if err = c.ReceiveFile("fc", "bob", msgC); err != nil {
                t.Fatal(err)
        }

        if err = a.RevokeFile("f"); err != nil {
                t.Fatal("RevokeFile falhou", err)
        }
        expectContent(t, a, "f", []byte("antes"))

        // Alice atualiza; Bob e Carol não podem ver.
        a.StoreFile("f", []byte("depois da revogacao"))
        expectNoAccess(t, b, "fb", []byte("depois da revogacao"))
        expectNoAccess(t, c, "fc", []byte("depois da revogacao"))
        a.AppendFile("f", []byte("+append"))
        expectNoAccess(t, b, "fb", []byte("depois da revogacao+append"))
        expectNoAccess(t, c, "fc", []byte("depois da revogacao+append"))

        // Bob e Carol não podem alterar o arquivo de Alice.
        b.StoreFile("fb", []byte("bob malicioso"))
        b.AppendFile("fb", []byte("lixo"))
        c.StoreFile("fc", []byte("carol maliciosa"))
        c.AppendFile("fc", []byte("lixo"))
        expectContent(t, a, "f", []byte("depois da revogacao+append"))

        // Reusar a mensagem antiga não devolve o acesso.
        if err = b.ReceiveFile("denovo", "alice", msgB); err == nil {
                expectNoAccess(t, b, "denovo", []byte("depois da revogacao+append"))
        }

        // Alice pode compartilhar de novo depois da revogação.
        msgB2, err := a.ShareFile("f", "bob")
        if err != nil {
                t.Fatal(err)
        }
        if err = b.ReceiveFile("nova", "alice", msgB2); err != nil {
                t.Fatal(err)
        }
        expectContent(t, b, "nova", []byte("depois da revogacao+append"))
}

func TestRevokeAfterAppendsAndRestart(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        b := initOrFail(t, "bob", "senha-b")
        a.StoreFile("f", []byte("1"))
        for i := 0; i < 5; i++ {
                a.AppendFile("f", []byte("x"))
        }
        msg, err := a.ShareFile("f", "bob")
        if err != nil {
                t.Fatal(err)
        }
        if err = b.ReceiveFile("g", "alice", msg); err != nil {
                t.Fatal(err)
        }
        b.AppendFile("g", []byte("b"))

        a2, err := GetUser("alice", "senha-a")
        if err != nil {
                t.Fatal(err)
        }
        if err = a2.RevokeFile("f"); err != nil {
                t.Fatal(err)
        }
        expectContent(t, a, "f", []byte("1xxxxxb"))
        expectContent(t, a2, "f", []byte("1xxxxxb"))
        a.AppendFile("f", []byte("novo"))
        expectNoAccess(t, b, "g", []byte("1xxxxxbnovo"))
}

func TestRevokeNonexistent(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        if err := a.RevokeFile("naoexiste"); err == nil {
                t.Error("RevokeFile deveria falhar para arquivo inexistente")
        }
}

func TestReceiveIntoExistingName(t *testing.T) {
        reset()
        a := initOrFail(t, "alice", "senha-a")
        b := initOrFail(t, "bob", "senha-b")
        a.StoreFile("f", []byte("de alice"))
        b.StoreFile("meu", []byte("de bob"))
        msg, err := a.ShareFile("f", "bob")
        if err != nil {
                t.Fatal(err)
        }
        b.ReceiveFile("meu", "alice", msg)
        // Independentemente do resultado, Bob deve conseguir ler algo
        // válido (nunca um valor misturado/corrompido).
        data, err := b.LoadFile("meu")
        if err == nil && !reflect.DeepEqual(data, []byte("de bob")) &&
                !reflect.DeepEqual(data, []byte("de alice")) {
                t.Error("Valor incorreto após ReceiveFile em nome existente")
        }
}