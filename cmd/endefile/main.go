package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

func encryptFile(key []byte, filePath string) error {
	plaintext, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer plaintext.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	encryptedFilePath := filePath + ".enc"
	encryptedFile, err := os.Create(encryptedFilePath)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	// Write the IV to the file
	if _, err := encryptedFile.Write(iv); err != nil {
		return err
	}

	// Encrypt the file contents and write to the file
	if _, err := io.Copy(&streamWriter{stream, encryptedFile}, plaintext); err != nil {
		return err
	}

	fmt.Printf("Encrypted file: %s\n", encryptedFilePath)
	return nil
}

func decryptFile(key []byte, filePath string) error {
	encryptedFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := encryptedFile.Read(iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	decryptedFilePath := filePath[:len(filePath)-4] // Remove the ".enc" extension
	decryptedFile, err := os.Create(decryptedFilePath)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	// Decrypt the file contents and write to the file
	if _, err := io.Copy(decryptedFile, &streamReader{stream, encryptedFile}); err != nil {
		return err
	}

	fmt.Printf("Decrypted file: %s\n", decryptedFilePath)
	return nil
}

type streamReader struct {
	stream cipher.Stream
	r      io.Reader
}

func (sr *streamReader) Read(p []byte) (n int, err error) {
	n, err = sr.r.Read(p)
	if err != nil {
		return
	}
	sr.stream.XORKeyStream(p[:n], p[:n])
	return
}

type streamWriter struct {
	stream cipher.Stream
	w      io.Writer
}

func (sw *streamWriter) Write(p []byte) (n int, err error) {
	sw.stream.XORKeyStream(p, p)
	return sw.w.Write(p)
}

func compressAndEncryptFolder(key []byte, folderPath string) error {
	compressedFilePath := folderPath + ".tar.gz"

	err := compressFolder(folderPath, compressedFilePath)
	if err != nil {
		return err
	}

	defer os.Remove(compressedFilePath) // Remove the compressed file after encryption

	err = encryptFile(key, compressedFilePath)
	if err != nil {
		return err
	}

	fmt.Printf("Encrypted folder: %s\n", compressedFilePath+".enc")
	return nil
}

func decompressAndDecryptFolder(key []byte, encryptedFolderPath string) error {
	decryptedFilePath := strings.TrimSuffix(encryptedFolderPath, ".enc")

	err := decryptFile(key, encryptedFolderPath)
	if err != nil {
		return err
	}

	defer os.Remove(encryptedFolderPath) // Remove the encrypted file after decryption

	err = decompressFile(encryptedFolderPath, decryptedFilePath, key)
	if err != nil {
		return err
	}

	fmt.Printf("Decrypted folder: %s\n", decryptedFilePath)
	return nil
}

func compressFolder(folderPath, compressedFilePath string) error {
	compressedFile, err := os.Create(compressedFilePath)
	if err != nil {
		return err
	}
	defer compressedFile.Close()

	gw := gzip.NewWriter(compressedFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(folderPath, path)
		if err != nil {
			return err
		}

		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tw, file); err != nil {
			return err
		}

		return nil
	})

	return err
}

func decompressFile(encryptedFilePath, decryptedFilePath string, key []byte) error {
	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	blockSize := aes.BlockSize

	iv := make([]byte, blockSize)
	if _, err := encryptedFile.Read(iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	decryptedFile, err := os.Create(decryptedFilePath)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	// Decrypt the contents of the file
	if _, err := io.Copy(decryptedFile, &streamReader{stream, encryptedFile}); err != nil {
		return err
	}

	return nil
}

func getPassword() ([]byte, error) {
	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	// Trim any leading/trailing whitespace
	password = []byte(strings.TrimSpace(string(password)))

	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

func deriveKeyFromPassword(password []byte) ([]byte, error) {
	salt := []byte("randomsalt")                           // Salt value for key derivation
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32) // Derive a 32-byte key
	return key, nil
}

func main() {
	compressFlag := flag.Bool("compress", false, "Compress the folder")
	decompressFlag := flag.Bool("decompress", false, "Decompress the folder")
	folderPath := flag.String("folder", "", "Path to the folder")
	flag.Parse()

	if (*compressFlag && *decompressFlag) || (!*compressFlag && !*decompressFlag) {
		fmt.Println("Please specify either -compress or -decompress flag")
		return
	}

	if *folderPath == "" {
		fmt.Println("Please provide the path to the folder using -folder flag")
		return
	}

	password, err := getPassword()
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	key, err := deriveKeyFromPassword(password)
	if err != nil {
		fmt.Println("Error deriving key from password:", err)
		return
	}

	if *compressFlag {
		err = compressAndEncryptFolder(key, *folderPath)
		if err != nil {
			fmt.Println("Error compressing and encrypting folder:", err)
			return
		}
	} else {
		err = decompressAndDecryptFolder(key, *folderPath)
		if err != nil {
			fmt.Println("Error decompressing and decrypting folder:", err)
			return
		}
	}
}
