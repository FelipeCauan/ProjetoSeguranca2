package proj2

// Você NÃO PODE alterar o que é importado. Se você adicionar QUALQUER
// importação adicional, o corretor automático quebrará.

import (
	// Você pode obter os pacotes necessários com
	// go mod download
	"github.com/RafaelTupynamba/Projeto2/userlib"

	// A vida fica muito mais fácil com json: você
	// vai querer usar isso para transformar facilmente
	// estruturas complexas em strings etc...
	"encoding/json"

	// Igualmente útil para depuração etc.
	"encoding/hex"

	// UUIDs são gerados com base no RNG criptográfico,
	// então vamos facilitar a vida e usar esses também...
	//
	"github.com/google/uuid"

	// Útil para mensagens de depuração ou manipulação de strings para chaves do datastore
	"strings"

	// Importação de errors
	"errors"

	// opcional
	_ "strconv"
	// Se você está procurando fmt, não fornecemos fmt, mas você pode usar userlib.DebugMsg
	// veja someUsefulThings() abaixo
)

// Esta função serve a dois propósitos: mostra alguns primitivos úteis
// e suprime avisos de itens que não estão sendo usados
func someUsefulThings() {
        // Cria um UUID aleatório
        f := uuid.New()
        userlib.DebugMsg("UUID como string:%v", f.String())

        // Exemplo de sobrescrever um byte de f
        f[0] = 10
        userlib.DebugMsg("UUID como string:%v", f.String())

        // Toma uma sequência de bytes e renderiza como hex
        h := hex.EncodeToString([]byte("fubar"))
        userlib.DebugMsg("O hex: %v", h)

        // Serializa dados em uma representação JSON
        // Funciona também com estruturas Go
        d, _ := json.Marshal(f)
        userlib.DebugMsg("Os dados JSON: %v", string(d))
        var g uuid.UUID
        json.Unmarshal(d, &g)
        userlib.DebugMsg("Dados desserializados %v", g.String())

        // Isso cria um tipo de erro
        userlib.DebugMsg("Criação de erro %v", errors.New(strings.ToTitle("Isso é um erro")))

        // E uma chave RSA aleatória. Neste caso, ignorando o
        // valor de retorno do erro
        var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
        pk, sk, _ = userlib.PKEKeyGen()
        userlib.DebugMsg("A chave é %v, %v", pk, sk)
}

// Função auxiliar: toma os primeiros 16 bytes
// e converte no tipo UUID
func bytesToUUID(data []byte) (ret uuid.UUID) {
        for x := range ret {
                ret[x] = data[x]
        }
        return
}

// FUNÇÕES AUXILIARES: derivação de chaves, padding, criptografia simétrica autenticada

const keyLen = 16 // tamanho das chaves AES e HMAC (userlib.AESKeySize)

// deriveKey implementa uma HKDF simples: HMAC(chave, propósito),
// truncado para keyLen bytes. Chaves diferentes para propósitos
// diferentes evitam reutilização de chave.
func deriveKey(key []byte, purpose string) ([]byte, error) {
        out, err := userlib.HMACEval(key, []byte(purpose))
        if err != nil {
                return nil, err
        }
        return out[:keyLen], nil
}

// deriveUUID gera um UUID determinístico (e imprevisível sem a chave)
// a partir de uma chave e de um rótulo.
func deriveUUID(key []byte, label []byte) (uuid.UUID, error) {
        out, err := userlib.HMACEval(key, label)
        if err != nil {
                return uuid.Nil, err
        }
        return uuid.FromBytes(out[:16])
}

// pad aplica padding PKCS#7. Necessário porque SymEnc usa AES-CBC
// e exige que o texto claro seja múltiplo do tamanho do bloco.
func pad(data []byte) []byte {
        n := userlib.AESBlockSize - len(data)%userlib.AESBlockSize
        out := make([]byte, len(data)+n)
        copy(out, data)
        for i := len(data); i < len(out); i++ {
                out[i] = byte(n)
        }
        return out
}

// unpad remove e valida o padding PKCS#7.
func unpad(data []byte) ([]byte, error) {
        if len(data) == 0 || len(data)%userlib.AESBlockSize != 0 {
                return nil, errors.New("padding inválido")
        }
        n := int(data[len(data)-1])
        if n == 0 || n > userlib.AESBlockSize {
                return nil, errors.New("padding inválido")
        }
        for i := len(data) - n; i < len(data); i++ {
                if int(data[i]) != n {
                        return nil, errors.New("padding inválido")
                }
        }
        return data[:len(data)-n], nil
}

// sealAndStore cifra (AES-CBC) e autentica (HMAC, Encrypt-then-MAC) os
// dados e os grava no datastore. O UUID de destino entra no MAC, então
// um atacante não consegue mover um registro válido para outro endereço.
func sealAndStore(id uuid.UUID, encKey []byte, macKey []byte, plaintext []byte) error {
        ct := userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSize), pad(plaintext))
        tag, err := userlib.HMACEval(macKey, append(id[:], ct...))
        if err != nil {
                return err
        }
        userlib.DatastoreSet(id, append(ct, tag...))
        return nil
}

// loadAndOpen busca, verifica o MAC e decifra um registro do datastore.
// found == false (e err == nil) significa que não existe nada em id.
func loadAndOpen(id uuid.UUID, encKey []byte, macKey []byte) (plaintext []byte, found bool, err error) {
        blob, ok := userlib.DatastoreGet(id)
        if !ok {
                return nil, false, nil
        }
        // Valida o tamanho ANTES de chamar SymDec (que entra em pânico
        // com entradas mal formadas): IV + pelo menos 1 bloco + tag.
        if len(blob) < userlib.HashSize+2*userlib.AESBlockSize ||
                (len(blob)-userlib.HashSize)%userlib.AESBlockSize != 0 {
                return nil, true, errors.New("registro corrompido")
        }
        ct := blob[:len(blob)-userlib.HashSize]
        tag := blob[len(blob)-userlib.HashSize:]
        expected, err := userlib.HMACEval(macKey, append(id[:], ct...))
        if err != nil {
                return nil, true, err
        }
        if !userlib.HMACEqual(tag, expected) {
                return nil, true, errors.New("integridade violada")
        }
        plaintext, err = unpad(userlib.SymDec(encKey, ct))
        if err != nil {
                return nil, true, err
        }
        return plaintext, true, nil
}

// Nomes usados no keystore (o keystore é confiável e público).
func pkeKeystoreName(username string) string { return "pke/" + username }
func dsKeystoreName(username string) string  { return "ds/" + username }

// USUÁRIO: cada usuário tem um registro no datastore, que contém
// o nome de usuário, a chave-mestra e as chaves privadas de assinatura
// e de decifragem. O registro é cifrado e autenticado com chaves derivadas

// Definição de estrutura para um registro de usuário.
// A struct guarda apenas dados imutáveis (chaves), então várias
// instâncias do mesmo usuário permanecem consistentes: todo estado
// mutável (arquivos) fica no datastore.
type User struct {
        Username string

        // Chave-mestra derivada de Argon2(senha, username).
        // Todas as outras chaves simétricas do usuário derivam dela.
        MasterKey []byte

        PKEDecKey userlib.PKEDecKey
        DSSignKey userlib.DSSignKey
}

// userKeys deriva da chave-mestra o endereço e as chaves do registro do usuário.
func userKeys(masterKey []byte) (id uuid.UUID, encKey []byte, macKey []byte, err error) {
        if id, err = deriveUUID(masterKey, []byte("user-uuid")); err != nil {
                return
        }
        if encKey, err = deriveKey(masterKey, "user-enc"); err != nil {
                return
        }
        macKey, err = deriveKey(masterKey, "user-mac")
        return
}

func masterKeyFor(username string, password string) []byte {
        // O username funciona como salt: usuários com a mesma senha
        // obtêm chaves diferentes.
        return userlib.Argon2Key([]byte(password), []byte("proj2-user/"+username), keyLen)
}

// Isso cria um usuário. Será chamado apenas uma vez por usuário
// (a menos que o keystore e o datastore sejam limpos durante testes).

// Deve armazenar uma cópia dos dados do usuário, devidamente criptografada,
// no datastore e deve armazenar a chave pública do usuário no keystore.

// O datastore pode corromper ou completamente apagar as informações
// armazenadas, mas ninguém de fora deve conseguir acessar os dados
// do usuário armazenados: o nome usado no datastore não deve ser
// descoberto sem também conhecer a senha e o nome de usuário.

// Não é permitido usar qualquer armazenamento global diferente
// do keystore e das funções de datastore da biblioteca userlib.

// Pode-se assumir que o usuário possui uma senha FORTE
func InitUser(username string, password string) (userdataptr *User, err error) {
        if username == "" {
                return nil, errors.New("nome de usuário vazio")
        }
        if _, exists := userlib.KeystoreGet(pkeKeystoreName(username)); exists {
                return nil, errors.New("usuário já existe")
        }
        if _, exists := userlib.KeystoreGet(dsKeystoreName(username)); exists {
                return nil, errors.New("usuário já existe")
        }

        var userdata User
        userdata.Username = username
        userdata.MasterKey = masterKeyFor(username, password)

        pkeEnc, pkeDec, err := userlib.PKEKeyGen()
        if err != nil {
                return nil, err
        }
        dsSign, dsVerify, err := userlib.DSKeyGen()
        if err != nil {
                return nil, err
        }
        userdata.PKEDecKey = pkeDec
        userdata.DSSignKey = dsSign

        if err = userlib.KeystoreSet(pkeKeystoreName(username), pkeEnc); err != nil {
                return nil, err
        }
        if err = userlib.KeystoreSet(dsKeystoreName(username), dsVerify); err != nil {
                return nil, err
        }

        id, encKey, macKey, err := userKeys(userdata.MasterKey)
        if err != nil {
                return nil, err
        }
        serialized, err := json.Marshal(userdata)
        if err != nil {
                return nil, err
        }
        if err = sealAndStore(id, encKey, macKey, serialized); err != nil {
                return nil, err
        }
        return &userdata, nil
}

// Isso recupera as informações do usuário do Datastore.
// Deve falhar com um erro se o usuário/senha for inválido,
// se os dados do usuário estiverem corrompidos,
// ou se o usuário não for encontrado.
func GetUser(username string, password string) (userdataptr *User, err error) {
        masterKey := masterKeyFor(username, password)
        id, encKey, macKey, err := userKeys(masterKey)
        if err != nil {
                return nil, err
        }
        plaintext, found, err := loadAndOpen(id, encKey, macKey)
        if err != nil {
                return nil, err
        }
        if !found {
                return nil, errors.New("usuário/senha inválidos")
        }
        var userdata User
        if err = json.Unmarshal(plaintext, &userdata); err != nil {
                return nil, err
        }
        if userdata.Username != username || !userlib.HMACEqual(userdata.MasterKey, masterKey) {
                return nil, errors.New("dados do usuário inconsistentes")
        }
        return &userdata, nil
}

// ARQUIVOS: cada arquivo é representado por uma entrada (fileEntry) que
// contém o UUID do metadado e a chave de arquivo. O metadado (fileMeta)
// contém a versão atual e o número de blocos. Cada bloco é armazenado
// separadamente no datastore, com UUID derivado da chave de arquivo,
// da versão e do índice do bloco.

type fileEntry struct {
        MetaUUID uuid.UUID
        FileKey  []byte
        IsOwner  bool
}

type fileMeta struct {
        Version   []byte // aleatório, muda a cada StoreFile
        NumChunks uint64
}

type fileKeys struct {
        enc []byte
        mac []byte
        loc []byte
}

func deriveFileKeys(fileKey []byte) (k fileKeys, err error) {
        if len(fileKey) != keyLen {
                return k, errors.New("chave de arquivo inválida")
        }
        if k.enc, err = deriveKey(fileKey, "file-enc"); err != nil {
                return
        }
        if k.mac, err = deriveKey(fileKey, "file-mac"); err != nil {
                return
        }
        k.loc, err = deriveKey(fileKey, "file-loc")
        return
}

func chunkUUID(k fileKeys, version []byte, index uint64) (uuid.UUID, error) {
        label := append([]byte("chunk/"), version...)
        for s := 56; s >= 0; s -= 8 {
                label = append(label, byte(index>>uint(s)))
        }
        return deriveUUID(k.loc, label)
}

// Endereço e chaves da entrada (ponteiro) de um arquivo para este usuário.
func (userdata *User) entryKeys(filename string) (id uuid.UUID, encKey []byte, macKey []byte, err error) {
        if id, err = deriveUUID(userdata.MasterKey, []byte("entry/"+filename)); err != nil {
                return
        }
        if encKey, err = deriveKey(userdata.MasterKey, "entry-enc"); err != nil {
                return
        }
        macKey, err = deriveKey(userdata.MasterKey, "entry-mac")
        return
}

func (userdata *User) loadEntry(filename string) (entry fileEntry, found bool, err error) {
        id, encKey, macKey, err := userdata.entryKeys(filename)
        if err != nil {
                return entry, false, err
        }
        plaintext, found, err := loadAndOpen(id, encKey, macKey)
        if err != nil || !found {
                return entry, found, err
        }
        if err = json.Unmarshal(plaintext, &entry); err != nil {
                return entry, true, err
        }
        if len(entry.FileKey) != keyLen {
                return entry, true, errors.New("entrada corrompida")
        }
        return entry, true, nil
}

func (userdata *User) storeEntry(filename string, entry fileEntry) error {
        id, encKey, macKey, err := userdata.entryKeys(filename)
        if err != nil {
                return err
        }
        serialized, err := json.Marshal(entry)
        if err != nil {
                return err
        }
        return sealAndStore(id, encKey, macKey, serialized)
}

func loadMeta(metaID uuid.UUID, k fileKeys) (meta fileMeta, err error) {
        plaintext, found, err := loadAndOpen(metaID, k.enc, k.mac)
        if err != nil {
                return meta, err
        }
        if !found {
                return meta, errors.New("arquivo não encontrado ou acesso revogado")
        }
        if err = json.Unmarshal(plaintext, &meta); err != nil {
                return meta, err
        }
        if len(meta.Version) != keyLen {
                return meta, errors.New("metadados corrompidos")
        }
        return meta, nil
}

func storeMeta(metaID uuid.UUID, k fileKeys, meta fileMeta) error {
        serialized, err := json.Marshal(meta)
        if err != nil {
                return err
        }
        return sealAndStore(metaID, k.enc, k.mac, serialized)
}

func storeChunk(k fileKeys, version []byte, index uint64, data []byte) error {
        id, err := chunkUUID(k, version, index)
        if err != nil {
                return err
        }
        return sealAndStore(id, k.enc, k.mac, data)
}

// deleteChunks apaga os blocos de uma versão (limpeza; não é crítico para segurança).
func deleteChunks(k fileKeys, meta fileMeta) {
        for i := uint64(0); i < meta.NumChunks; i++ {
                if id, err := chunkUUID(k, meta.Version, i); err == nil {
                        userlib.DatastoreDelete(id)
                }
        }
}

// readContents lê e verifica todos os blocos de um arquivo.
func readContents(metaID uuid.UUID, fileKey []byte) (data []byte, k fileKeys, meta fileMeta, err error) {
        if k, err = deriveFileKeys(fileKey); err != nil {
                return
        }
        if meta, err = loadMeta(metaID, k); err != nil {
                return
        }
        data = make([]byte, 0)
        for i := uint64(0); i < meta.NumChunks; i++ {
                id, e := chunkUUID(k, meta.Version, i)
                if e != nil {
                        return nil, k, meta, e
                }
                chunk, found, e := loadAndOpen(id, k.enc, k.mac)
                if e != nil {
                        return nil, k, meta, e
                }
                if !found {
                        return nil, k, meta, errors.New("bloco do arquivo ausente")
                }
                data = append(data, chunk...)
        }
        return data, k, meta, nil
}

// writeNewVersion grava data como uma versão nova (Version aleatória,
// um único bloco) em metaID e apaga os blocos da versão anterior.
func writeNewVersion(metaID uuid.UUID, k fileKeys, data []byte, old *fileMeta) error {
        meta := fileMeta{Version: userlib.RandomBytes(keyLen), NumChunks: 1}
        if err := storeChunk(k, meta.Version, 0, data); err != nil {
                return err
        }
        if err := storeMeta(metaID, k, meta); err != nil {
                return err
        }
        if old != nil {
                deleteChunks(k, *old)
        }
        return nil
}

// Isso armazena um arquivo no datastore.
//
// O nome do arquivo NÃO deve ser revelado ao datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
        entry, found, err := userdata.loadEntry(filename)
        if err == nil && found {
                // Arquivo já existe (próprio ou compartilhado): sobrescreve
                // no mesmo lugar, para que todos com acesso vejam a mudança.
                k, err := deriveFileKeys(entry.FileKey)
                if err != nil {
                        return
                }
                var old *fileMeta
                if meta, err := loadMeta(entry.MetaUUID, k); err == nil {
                        old = &meta
                }
                writeNewVersion(entry.MetaUUID, k, data, old)
                return
        }

        // Arquivo novo: local e chave aleatórios.
        entry = fileEntry{MetaUUID: uuid.New(), FileKey: userlib.RandomBytes(keyLen), IsOwner: true}
        k, err := deriveFileKeys(entry.FileKey)
        if err != nil {
                return
        }
        if err = writeNewVersion(entry.MetaUUID, k, data, nil); err != nil {
                return
        }
        userdata.storeEntry(filename, entry)
}

// Isso adiciona dados a um arquivo existente.
//
// Append deve ser eficiente: você não deve reescrever ou recriptografar
// o arquivo existente, mas apenas a informação adicional
// e metadados necessários.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
        entry, found, err := userdata.loadEntry(filename)
        if err != nil {
                return err
        }
        if !found {
                return errors.New("arquivo não encontrado")
        }
        k, err := deriveFileKeys(entry.FileKey)
        if err != nil {
                return err
        }
        meta, err := loadMeta(entry.MetaUUID, k)
        if err != nil {
                return err
        }
        // Só gravamos o bloco novo e os metadados: custo independe do tamanho do arquivo.
        if err = storeChunk(k, meta.Version, meta.NumChunks, data); err != nil {
                return err
        }
        meta.NumChunks++
        return storeMeta(entry.MetaUUID, k, meta)
}

// Isso carrega um arquivo do Datastore.
//
// Deve retornar um erro se o arquivo estiver corrompido de qualquer forma.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
        entry, found, err := userdata.loadEntry(filename)
        if err != nil {
                return nil, err
        }
        if !found {
                return nil, nil
        }
        data, _, _, err = readContents(entry.MetaUUID, entry.FileKey)
        if err != nil {
                return nil, err
        }
        return data, nil
}

/*
A mensagem de compartilhamento usa criptografia híbrida, porque o
RSA-OAEP/SHA-512 com 2048 bits só cifra ~126 bytes:

  K   = 16 bytes aleatórios
  rsa = PKEEnc(chave pública do destinatário, K)
  ct  = SymEnc(enc(K), { Payload, Sig })   com Sig = DSSign(remetente, Payload)
  tag = HMAC(mac(K), rsa || ct)

Payload = { Sender, Recipient, MetaUUID, FileKey }. A assinatura fica
DENTRO da parte cifrada, então um observador não consegue verificá-la
contra o keystore e descobrir quem é o remetente. O nome do arquivo do
remetente nunca é incluído.
*/

// Você pode querer definir o que exatamente deseja passar como
// sharingRecord para serializar/desserializar no datastore.
type sharingRecord struct {
        Sender    string
        Recipient string
        MetaUUID  uuid.UUID
        FileKey   []byte
}

type signedRecord struct {
        Payload []byte
        Sig     []byte
}

type sharingMessage struct {
        RSA []byte
        Ct  []byte
        Tag []byte
}

// Isso cria um registro de compartilhamento, que é uma chave
// apontando para algo no datastore para compartilhar com o destinatário.

// Isso habilita o destinatário a acessar o arquivo criptografado
// tanto para leitura quanto para append.

// Nem o destinatário NEM o datastore devem obter qualquer
// informação sobre como o remetente chama o arquivo. Apenas o
// destinatário pode acessar o registro de compartilhamento, e apenas
// o destinatário deve ser capaz de saber quem é o remetente.

func (userdata *User) ShareFile(filename string, recipient string) (
        magic_string string, err error) {

        entry, found, err := userdata.loadEntry(filename)
        if err != nil {
                return "", err
        }
        if !found {
                return "", errors.New("arquivo não encontrado")
        }
        // Garante que ainda temos acesso válido antes de compartilhar.
        k, err := deriveFileKeys(entry.FileKey)
        if err != nil {
                return "", err
        }
        if _, err = loadMeta(entry.MetaUUID, k); err != nil {
                return "", err
        }

        recipientKey, ok := userlib.KeystoreGet(pkeKeystoreName(recipient))
        if !ok {
                return "", errors.New("destinatário não encontrado")
        }

        payload, err := json.Marshal(sharingRecord{
                Sender:    userdata.Username,
                Recipient: recipient,
                MetaUUID:  entry.MetaUUID,
                FileKey:   entry.FileKey,
        })
        if err != nil {
                return "", err
        }
        sig, err := userlib.DSSign(userdata.DSSignKey, payload)
        if err != nil {
                return "", err
        }
        inner, err := json.Marshal(signedRecord{Payload: payload, Sig: sig})
        if err != nil {
                return "", err
        }

        msgKey := userlib.RandomBytes(keyLen)
        encKey, err := deriveKey(msgKey, "share-enc")
        if err != nil {
                return "", err
        }
        macKey, err := deriveKey(msgKey, "share-mac")
        if err != nil {
                return "", err
        }
        rsaCt, err := userlib.PKEEnc(recipientKey, msgKey)
        if err != nil {
                return "", err
        }
        ct := userlib.SymEnc(encKey, userlib.RandomBytes(userlib.AESBlockSize), pad(inner))
        tag, err := userlib.HMACEval(macKey, append(append([]byte{}, rsaCt...), ct...))
        if err != nil {
                return "", err
        }

        msg, err := json.Marshal(sharingMessage{RSA: rsaCt, Ct: ct, Tag: tag})
        if err != nil {
                return "", err
        }
        return hex.EncodeToString(msg), nil
}

// O nome do arquivo do destinatário pode ser diferente do nome
// do arquivo do remetente. O destinatário não deve ser capaz de
// descobrir como o remetente vê o nome do arquivo! No entanto, o
// destinatário deve garantir que a mensagem é autenticamente do remetente.
func (userdata *User) ReceiveFile(filename string, sender string,
        magic_string string) error {

        if _, found, err := userdata.loadEntry(filename); err != nil || found {
                return errors.New("já existe um arquivo com esse nome")
        }

        raw, err := hex.DecodeString(magic_string)
        if err != nil {
                return err
        }
        var msg sharingMessage
        if err = json.Unmarshal(raw, &msg); err != nil {
                return err
        }

        msgKey, err := userlib.PKEDec(userdata.PKEDecKey, msg.RSA)
        if err != nil {
                return err
        }
        if len(msgKey) != keyLen {
                return errors.New("mensagem inválida")
        }
        encKey, err := deriveKey(msgKey, "share-enc")
        if err != nil {
                return err
        }
        macKey, err := deriveKey(msgKey, "share-mac")
        if err != nil {
                return err
        }
        expected, err := userlib.HMACEval(macKey, append(append([]byte{}, msg.RSA...), msg.Ct...))
        if err != nil {
                return err
        }
        if !userlib.HMACEqual(expected, msg.Tag) {
                return errors.New("mensagem adulterada")
        }
        if len(msg.Ct) < 2*userlib.AESBlockSize || len(msg.Ct)%userlib.AESBlockSize != 0 {
                return errors.New("mensagem inválida")
        }
        inner, err := unpad(userlib.SymDec(encKey, msg.Ct))
        if err != nil {
                return err
        }
        var signed signedRecord
        if err = json.Unmarshal(inner, &signed); err != nil {
                return err
        }

        // Autentica o remetente.
        verifyKey, ok := userlib.KeystoreGet(dsKeystoreName(sender))
        if !ok {
                return errors.New("remetente não encontrado")
        }
        if err = userlib.DSVerify(verifyKey, signed.Payload, signed.Sig); err != nil {
                return err
        }
        var record sharingRecord
        if err = json.Unmarshal(signed.Payload, &record); err != nil {
                return err
        }
        if record.Sender != sender || record.Recipient != userdata.Username {
                return errors.New("mensagem não destinada a este usuário")
        }

        // Verifica que o arquivo ainda existe (falha se o acesso foi revogado).
        k, err := deriveFileKeys(record.FileKey)
        if err != nil {
                return err
        }
        if _, err = loadMeta(record.MetaUUID, k); err != nil {
                return err
        }

        return userdata.storeEntry(filename, fileEntry{
                MetaUUID: record.MetaUUID,
                FileKey:  record.FileKey,
                IsOwner:  false,
        })
}

// Remove o acesso de todos os outros.
//
// O dono move o arquivo para um UUID novo e aleatório, cifrado com uma
// chave nova, e apaga a cópia antiga. Os demais usuários só conhecem o
// ponteiro antigo, que deixa de existir; eles não conseguem descobrir
// (nem sobrescrever) o novo local.
func (userdata *User) RevokeFile(filename string) (err error) {
        entry, found, err := userdata.loadEntry(filename)
        if err != nil {
                return err
        }
        if !found {
                return errors.New("arquivo não encontrado")
        }
        if !entry.IsOwner {
                return errors.New("apenas o criador do arquivo pode revogar")
        }

        data, oldKeys, oldMeta, err := readContents(entry.MetaUUID, entry.FileKey)
        if err != nil {
                return err
        }

        newEntry := fileEntry{MetaUUID: uuid.New(), FileKey: userlib.RandomBytes(keyLen), IsOwner: true}
        newKeys, err := deriveFileKeys(newEntry.FileKey)
        if err != nil {
                return err
        }
        if err = writeNewVersion(newEntry.MetaUUID, newKeys, data, nil); err != nil {
                return err
        }
        if err = userdata.storeEntry(filename, newEntry); err != nil {
                return err
        }

        // Apaga a cópia antiga.
        deleteChunks(oldKeys, oldMeta)
        userlib.DatastoreDelete(entry.MetaUUID)
        return nil
}