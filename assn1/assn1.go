package assn1

//package main

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	//"fmt"

	userlib "github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

type FileInfo struct {
	FileName string
	FileUUID string // key is filename_username value is fileuuid
}

//User : User structure used to store the user information
type User struct {
	Username        string
	Password        string
	PrivateKey      userlib.PrivateKey
	AccessibleFiles []FileInfo
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type UserSalt struct {
	Salt []byte
	Hmac string
}

//func (userdata *User) AddfileInfo(item FileInfo) {
//	userdata.AccessibleFiles = append(userdata.AccessibleFiles, item)
//}

func SHAgenerate(data string) (hashedData string) {
	hash := userlib.NewSHA256()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

type sharingRecord struct {
	SymmKey []byte
	Hmac    []string
	//Counter           int @aakj
	IV                []byte
	Salt              []byte
	DirectPointerInfo string
}

//type hashedUUID struct {
//	HashedUUIDkey string
//}

type DirectPointer struct {
	DirectPointerkey []Pointer
}

type Pointer struct {
	Item string
	Num  int
}

type Block struct {
	Blockkey []byte
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	if len(data) < configBlockSize {
		return errors.New("Blocksize is less than required")
	}

	actualFilename := userdata.Username + filename
	length := len(userdata.AccessibleFiles)

	i := 0

	fileUU := uuid.New()
	fileUUID := fileUU.String()

	for i = 0; i < length; i++ {
		if userdata.AccessibleFiles[i].FileName == actualFilename {
			fileUUID = userdata.AccessibleFiles[i].FileUUID
			break
		}
	}

	//Generate UUID
	//fileUUID := uuid.New()

	//Hashed UUID
	//	fileHashedUUID := SHAgenerate(fileUUID.String())

	//	var f sharingRecord
	f := new(sharingRecord)
	//f.Counter = 1 @aak

	//Encrypt data
	key := userlib.RandomBytes(userlib.AESKeySize)
	ciphertext := make([]byte, len(data))
	iv := userlib.RandomBytes(userlib.AESKeySize) //@aak
	stream := userlib.CFBEncrypter(key, iv)
	stream.XORKeyStream(ciphertext, data)
	//fmt.Print("\nCiphet", ciphertext, "\n data",
	f.SymmKey = key
	f.IV = iv

	//Block storage
	blockUUID := uuid.New()
	//	var b Block
	b := new(Block)
	b.Blockkey = ciphertext
	val1, _ := json.Marshal(b)
	userlib.DatastoreSet(blockUUID.String(), val1)

	//Pointer generate
	pointerUUID := uuid.New()
	//var p Pointer
	p := new(Pointer)
	p.Item = blockUUID.String()
	p.Num = 0
	val2, _ := json.Marshal(p)
	userlib.DatastoreSet(pointerUUID.String(), val2)

	//Appending with other pointers
	directPointerUUID := uuid.New()
	//var dp *DirectPointer
	dp := new(DirectPointer)
	//fmt.Print("\nBEFORE STORE: ", len(dp.DirectPointerkey))
	dp.DirectPointerkey = append(dp.DirectPointerkey, *p)
	//fmt.Print("\nAFTER STORE: ", len(dp.DirectPointerkey))
	//	fmt.Print("store direct pointer key", &(dp.DirectPointerkey))
	val3, _ := json.Marshal(dp)
	userlib.DatastoreSet(directPointerUUID.String(), val3)
	vala, ok := userlib.DatastoreGet(directPointerUUID.String())
	if !ok {
		return errors.New("Something went wrong")
	}
	var a DirectPointer
	json.Unmarshal(vala, &a)
	//	fmt.Print("data get ", len(a.DirectPointerkey))

	//No need to use struct HashedUUID, infact store directly.
	//no need to use fileHashedUUID
	//	userlib.DatastoreSet(fileHashedUUID, []byte(directPointerUUID.String()))
	//	userlib.DatastoreSet(fileHashedUUID, []byte(directPointerUUID.String()))
	//valFileHashedUUID:=json.Marshal(directPointerUUID.String())
	//	userlib.DatastoreSet(fileHashedUUID, valFileHashedUUID)

	//to be applied on ciphertext
	//HMAC on file data
	salt := userlib.RandomBytes(256)
	//	hmac := applyHMAC(salt, data)
	hMac := applyHMAC(salt, ciphertext)
	f.Hmac = append(f.Hmac, hMac)
	f.Salt = salt
	f.DirectPointerInfo = directPointerUUID.String()

	//correct
	//To store symmKey, Hmac etc.
	val4, _ := json.Marshal(f)
	userlib.DatastoreSet(fileUUID, val4)

	//No need to use FileInfo. Access FileUUID using username+filename. But this might create problem
	//A shares with B and B with C, then how will C know username of owner. Since this concept was already
	//present so have not modified.
	//not required as it is directly stored in User
	//fileInfo FileInfo
	fileInfo := new(FileInfo)
	fileInfo.FileUUID = fileUUID
	fileInfo.FileName = (userdata.Username + filename)
	//	valFileInfo, _ := json.Marshal(fileInfo)
	//userlib.DatastoreSet(userdata.Username+filename, json.Marshal(fileUUID.String()))

	//reflect changes to user in datastore
	val5, ok := userlib.DatastoreGet(userdata.Username + userdata.Password)
	if !ok {
		return errors.New("Something went wrong")
	}
	//var u UserSalt
	u := new(UserSalt)
	json.Unmarshal(val5, &u)
	salt = u.Salt
	userdata.AccessibleFiles = append(userdata.AccessibleFiles, *fileInfo)
	//length := len(userdata.AccessibleFiles)
	//	fmt.Print(" Count Accessible files ", length)
	hashedPassword := userlib.Argon2Key([]byte(userdata.Password), salt, 256)
	//correct I guess
	val6, _ := json.Marshal(userdata)
	//fmt.Print("Accessible files ", val6)
	userlib.DatastoreSet(string(hashedPassword), val6)

	//reflect changes to UserSalt
	u.Hmac = applyHMAC(salt, val6)
	val7, _ := json.Marshal(u)
	userlib.DatastoreSet(userdata.Username+userdata.Password, val7)

	return nil
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	if len(data) < configBlockSize {
		return errors.New("Blocksize is less than required")
	}
	actualFilename := userdata.Username + filename
	length := len(userdata.AccessibleFiles)
	fileUUID := ""
	i := 0

	for i = 0; i < length; i++ {
		if userdata.AccessibleFiles[i].FileName == actualFilename {
			fileUUID = userdata.AccessibleFiles[i].FileUUID
			break
		}
	}
	if fileUUID == "" {
		return errors.New("Can't access file or something went wrong") //@aak
	} else {
		val1, ok := userlib.DatastoreGet(fileUUID)
		sr := new(sharingRecord)
		json.Unmarshal(val1, &sr)
		//fmt.Print("\nSR: ", sr)
		if !ok {
			return errors.New("File not found or something went wrong") //@aak
		} else {
			directPointerArr, ok := userlib.DatastoreGet(sr.DirectPointerInfo)
			if !ok {
				return errors.New("File corrupted") //@aak
			}
			dpa := new(DirectPointer)
			json.Unmarshal(directPointerArr, &dpa)
			//fmt.Print("\nDPA: ", dpa)
			length = len(dpa.DirectPointerkey)
			//fmt.Print("\nLENGTHAPPEND :", length)

			// check if hmac matches
			for i = 0; i < length; i++ {
				dta, ok := userlib.DatastoreGet(dpa.DirectPointerkey[i].Item)
				if !ok {
					//fmt.Print("\nI: ", i)
					return errors.New("Something went wrong ") //@aak
				}
				b := new(Block)
				json.Unmarshal(dta, &b)
				newHMAC := applyHMAC(sr.Salt, b.Blockkey)
				isHMACEqual := userlib.Equal([]byte(sr.Hmac[i]), []byte(newHMAC))
				if !isHMACEqual {
					return errors.New("data has been corrupted")
				}
			}

			//get new block same code as store data
			ciphertext := make([]byte, len(data))
			stream := userlib.CFBEncrypter(sr.SymmKey, sr.IV)
			stream.XORKeyStream(ciphertext, data)

			//Block storage
			blockUUID := uuid.New()
			b := new(Block)
			b.Blockkey = ciphertext
			val1, _ := json.Marshal(b)
			userlib.DatastoreSet(blockUUID.String(), val1)

			//Pointer generate
			pointerUUID := uuid.New()
			p := new(Pointer)
			p.Item = blockUUID.String()
			p.Num = length
			//fmt.Print("\np.num: ", p.Num)
			//fmt.Print("\nDATA :", data)
			val2, _ := json.Marshal(p)
			userlib.DatastoreSet(pointerUUID.String(), val2)

			//append
			//fmt.Print("\nBEFORE STORE: ", len(dpa.DirectPointerkey))
			dpa.DirectPointerkey = append(dpa.DirectPointerkey, *p)
			//fmt.Print("\nAFTER STORE: ", len(dpa.DirectPointerkey))
			val3, _ := json.Marshal(dpa)
			userlib.DatastoreSet(sr.DirectPointerInfo, val3)

			//hmac on new block
			hMac := applyHMAC(sr.Salt, ciphertext)
			sr.Hmac = append(sr.Hmac, hMac)
			val4, _ := json.Marshal(sr)
			userlib.DatastoreSet(fileUUID, val4)
		}
	}
	return nil
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	actualFilename := userdata.Username + filename
	length := len(userdata.AccessibleFiles)
	fileUUID := ""
	i := 0
	dataBlock := new(Block)

	for i = 0; i < length; i++ {
		if userdata.AccessibleFiles[i].FileName == actualFilename {
			fileUUID = userdata.AccessibleFiles[i].FileUUID
			break
		}
	}
	if fileUUID == "" {
		return nil, errors.New("Can't access file or something went wrong") //@aak
	} else {
		val1, ok := userlib.DatastoreGet(fileUUID)
		sr := new(sharingRecord)
		json.Unmarshal(val1, &sr)
		if !ok {
			return nil, errors.New("File not found or something went wrong") //@aak
		} else {
			directPointerArr, ok := userlib.DatastoreGet(sr.DirectPointerInfo)
			if !ok {
				return nil, errors.New("File corrupted")
			}
			dpa := new(DirectPointer)
			json.Unmarshal(directPointerArr, &dpa)
			length = len(dpa.DirectPointerkey)

			if offset < 0 || offset >= length {
				return nil, errors.New("Invalid Offset")
			}
			// check if hmac matches and find block
			for i = 0; i < length; i++ {
				if i != dpa.DirectPointerkey[i].Num { //@aak better start Num from 0
					return nil, errors.New("block has been corrupted")
				}
				data, ok := userlib.DatastoreGet(dpa.DirectPointerkey[i].Item)
				if !ok {
					return nil, errors.New("Something corrupted") //@aak
				}
				b := new(Block)
				json.Unmarshal(data, &b)

				newHMAC := applyHMAC(sr.Salt, b.Blockkey)
				isHMACEqual := userlib.Equal([]byte(sr.Hmac[i]), []byte(newHMAC))
				if !isHMACEqual {
					return nil, errors.New("data has been corrupted")
				}
				if i == offset {
					dataBlock = b
					//fmt.Print("OFFSET: ", i)
					//fmt.Print("DATA: ", dataBlock.Blockkey)
				}
			}

			// decrypt data block
			plaintext := make([]byte, len(dataBlock.Blockkey))
			stream := userlib.CFBDecrypter(sr.SymmKey, sr.IV)
			stream.XORKeyStream(plaintext, dataBlock.Blockkey)

			return plaintext, nil
		}
	}
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	if userdata.Username == recipient {
		return "", errors.New("Can't share file with oneself")
	}
	//whether can access file or not
	actualFilename := userdata.Username + filename
	length := len(userdata.AccessibleFiles)
	fileUUID := ""
	i := 0
	var send []byte
	var encMsg []byte

	for i = 0; i < length; i++ {
		if userdata.AccessibleFiles[i].FileName == actualFilename {
			fileUUID = userdata.AccessibleFiles[i].FileUUID
			break
		}
	}
	if fileUUID == "" {
		return "", errors.New("Can't access file or something went wrong")
	} else {
		//fmt.Print("\nUUID SEND: ", fileUUID)
		recPub, ok := userlib.KeystoreGet(recipient)
		if !ok {
			return "", errors.New("Recepient doesn't exist or something went wrong")
		}
		encMsg, _ = userlib.RSAEncrypt(&recPub, []byte(fileUUID), nil)
		send, _ = userlib.RSASign(&userdata.PrivateKey, encMsg)
	}
	//fmt.Print("\nUUID: ", fileUUID)
	//fmt.Print("\nSEND_PART1 :", string(send))
	//fmt.Print("\nENC_MSG_PART2 :", string(encMsg))
	return string(send) + string(encMsg), nil
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	//@aak missing RSAverify and RSASign
	var receive []byte
	var part1 string
	var part2 string
	part1 = msgid[0:256]
	part2 = msgid[256:]
	//fmt.Print("\nSEND_PART1 :", part1)
	//fmt.Print("\nENC_MSG_PART2 :", part2)
	sendPub, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Recepient doesn't exist or something went wrong")
	}
	er := userlib.RSAVerify(&sendPub, []byte(part2), []byte(part1))
	if er != nil {
		return er
	}
	receive, er = userlib.RSADecrypt(&userdata.PrivateKey, []byte(part2), nil)
	if er != nil {
		return er
	}
	//fmt.Print("\nUUID RECV: ", string(receive))
	fileInfo := new(FileInfo)
	fileInfo.FileUUID = string(receive)
	fileInfo.FileName = (userdata.Username + filename)
	userdata.AccessibleFiles = append(userdata.AccessibleFiles, *fileInfo)

	u := new(UserSalt)
	val1, ok := userlib.DatastoreGet(userdata.Username + userdata.Password)
	if !ok {
		return errors.New("Something went wrong")
	}
	json.Unmarshal(val1, &u)
	salt := u.Salt
	hashedPassword := userlib.Argon2Key([]byte(userdata.Password), salt, 256)
	val2, _ := json.Marshal(userdata)
	userlib.DatastoreSet(string(hashedPassword), val2)

	u.Hmac = applyHMAC(salt, val2)
	val3, _ := json.Marshal(u)
	userlib.DatastoreSet(userdata.Username+userdata.Password, val3)

	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	//@aak missing symmkey change
	newfileUUID := uuid.New()
	actualFilename := userdata.Username + filename
	length := len(userdata.AccessibleFiles)
	fileUUID := ""
	i := 0

	for i = 0; i < length; i++ {
		if userdata.AccessibleFiles[i].FileName == actualFilename {
			fileUUID = userdata.AccessibleFiles[i].FileUUID
			break
		}
	}
	if fileUUID == "" {
		return errors.New("Can't access file or something went wrong") //@aak
	} else {
		val1, ok := userlib.DatastoreGet(fileUUID)
		sr := new(sharingRecord)
		json.Unmarshal(val1, &sr)
		if !ok {
			return errors.New("File not found or something went wrong") //@aak
		} else {
			newsr := new(sharingRecord)
			newsr = sr
			val2, _ := json.Marshal(newsr)
			userlib.DatastoreSet(newfileUUID.String(), val2)
			userlib.DatastoreDelete(fileUUID)

			userdata.AccessibleFiles[i].FileUUID = newfileUUID.String()
			val3, ok := userlib.DatastoreGet(userdata.Username + userdata.Password)
			if !ok {
				return errors.New("Something went wrong")
			}
			var us UserSalt
			json.Unmarshal(val3, &us)
			hashedPassword := userlib.Argon2Key([]byte(userdata.Password), us.Salt, 256)
			val4, _ := json.Marshal(userdata)
			userlib.DatastoreSet(string(hashedPassword), val4)

			sha := applyHMAC(us.Salt, val4)
			us.Hmac = sha
			val5, _ := json.Marshal(us)
			userlib.DatastoreSet(userdata.Username+userdata.Password, val5)
		}
	}

	return nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {

	var user *User
	user = new(User)

	if len(username) != 0 && len(password) != 0 {
		user.Username = username
		user.Password = password
	} else {
		return nil, errors.New("username or passwrd can not be empty")
	}

	// check if username already exist in db

	_, ok := userlib.KeystoreGet(username)
	if ok {
		return nil, errors.New("username already exist")
	} else {
		var key *userlib.PrivateKey
		key, _ = userlib.GenerateRSAKey()
		userlib.DebugMsg("Key is %v", key)
		user.PrivateKey = *key
		rsaPublicKey := key.PublicKey //@aak
		userlib.KeystoreSet(username, rsaPublicKey)

		//generate argon2key
		salt := (userlib.RandomBytes(256))
		hashedPassword := userlib.Argon2Key([]byte(password), salt, 256)

		//fmt.Print("hashedPwd= ", hashedPassword)

		//datastore
		val, _ := json.Marshal(user)
		userlib.DatastoreSet(string(hashedPassword), val)

		//apply hmac on hashedPassword after marshiling it
		sha := applyHMAC(salt, val)
		//fmt.Print("hash", hash.Write(val))

		//	fmt.Println("hash hmac", sha)
		//fmt.Print("hash encoded", sha)
		//var userSalt *UserSalt
		keyUsernamePwd := username + password
		userSalt := new(UserSalt)
		userSalt.Salt = salt
		userSalt.Hmac = sha
		val2, _ := json.Marshal(userSalt)
		userlib.DatastoreSet(keyUsernamePwd, val2)
	}

	return user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {

	//	user := new(User)
	userSalt := new(UserSalt)

	//find salt from datastore
	val1, ok := userlib.DatastoreGet(username + password)
	if !ok {
		return nil, errors.New("Wrong usernme or pwd")
	}

	var us UserSalt
	json.Unmarshal(val1, &us)
	userSalt.Salt = us.Salt
	//fmt.Println("\nDatastoreGet salt", us.Salt, "\nDatastore hmac", us.Hmac)

	//generate argon2key from provided pwd
	hashedPassword := userlib.Argon2Key([]byte(password), userSalt.Salt, 256)
	val2, ok := userlib.DatastoreGet(string(hashedPassword))
	var u *User
	// error implement
	if ok {

		json.Unmarshal(val2, &u)
		//	fmt.Println("DatastoreGet hashedPwd", u)
	} else {
		return nil, errors.New("Something is Wrong")
	}

	oldHMAC := us.Hmac
	newHMAC := applyHMAC(us.Salt, val2)

	isHMACEqual := userlib.Equal([]byte(oldHMAC), []byte(newHMAC))

	if !isHMACEqual {
		return nil, errors.New("Fail! Data has been changed maliciously")
	} else {
		//fmt.Println("Succcess! Data has not beem modified")
	}

	//	value, _ := userlib.KeystoreGet(username)
	//	fmt.Print(value)

	return u, nil
}

func applyHMAC(salt []byte, val []byte) string {
	hash := userlib.NewHMAC(salt)
	hash.Write(val)
	return hex.EncodeToString(hash.Sum(nil))
}

/*
func main() {
	//	fmt.Print("Go runs on ")
	user1, err1 := InitUser("aj", "123")
	//user2, err2 := GetUser("aak", "123")
	user3, err3 := InitUser("ap", "123")
	//fmt.Print(user)
	//fmt.Println("\nUser1 ", user1)
	//fmt.Println("\nUser2 ", user2)
	fmt.Println("\nUser3 ", user3)
	fmt.Print("\nerr1 ", err1)
	//fmt.Print("\nerr2 ", err2)
	fmt.Print("\nerr3 ", err3)
	err12 := user1.StoreFile("f1", []byte("data1"))
	fmt.Print("\nerr12 ", err12)
	//user1.StoreFile("f2", []byte("data1"))
	err13 := user1.AppendFile("f1", []byte("data2"))
	fmt.Print("\nerr13 ", err13)
	err14 := user1.AppendFile("f1", []byte("data3"))
	fmt.Print("\nerr14 ", err14)
	//user1.AppendFile("f2", []byte("data2"))

	//user1.AppendFile("f2", []byte("data3"))
	data1, err6 := user1.LoadFile("f1", 0)
	fmt.Print("\ndata1: ", data1)
	fmt.Print("\nerr6 ", err6)
	data2, err7 := user1.LoadFile("f1", 1)
	fmt.Print("\ndata2: ", data2)
	fmt.Print("\nerr7 ", err7)
	data3, err8 := user1.LoadFile("f1", 3)
	fmt.Print("\ndata3: ", data3)
	fmt.Print("\nerr8 ", err8)
	data4, err15 := user1.LoadFile("f1", 4)
	fmt.Print("\ndata4: ", data4)
	fmt.Print("\nerr15 ", err15)
	id1, err4 := user1.ShareFile("f1", "ap")
	fmt.Print("\nid1 ", id1)
	fmt.Print("\nerr4 ", err4)
	err16 := user3.ReceiveFile("f1", "ap", id1)
	fmt.Print("\nerr16 ", err16)
	//id2, err5 := user1.ShareFile("f2", "ap")
	//fmt.Print("\nerr5 ", err5)
	//user3.ReceiveFile("f2", "ap", id2)
	//err9 := user1.RevokeFile("f2")
	//fmt.Print("\nerr9 ", err9)
	//err10 := user3.AppendFile("f2", []byte("data4"))
	//fmt.Print("\nerr10 ", err10)
	//err11 := user3.AppendFile("f1", []byte("data4"))
	//fmt.Print("\nerr11 ", err11)
	//h := hex.EncodeToString([]byte("fubar"))
	//	fmt.Print("The hex: %v", h)
	//d, _ := json.Marshal("apoorva")
	//fmt.Println("The json data: %v", string(d))
	//var g
	//json.Unmarshal(d, &g)
	//fmt.Println("Unmashaled data %v", g.String())
}
*/
