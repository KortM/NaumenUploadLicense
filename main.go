package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	configparser "github.com/bigkevmcd/go-configparser"

	_ "github.com/mattn/go-sqlite3"
)

var (
	email      string
	passwd     string
	server     string
	port       string
	recepient  []string
	keystore   string
	folder     string
	fileName   string
	configPath string
	dbPath     string
)

func main() {
	fmt.Fprintln(os.Stdout, "Скрипт запущен", time.Now())
	var err error
	folder, err = filepath.Abs("certs/")
	if err != nil {
		log.Fatal(err)
	}
	fileName, err = filepath.Abs(folder + "/cert.crt")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Путь для сертификата:\n%s\n", fileName)
	configPath, err = filepath.Abs("config.cfg")
	if err != nil {
		log.Fatal(err)
	}
	dbPath, err = filepath.Abs("certs_db.db")
	if err != nil {
		log.Fatal(err)
	}
	ParseConfig(configPath)
	not_before, cert_name := GetCertDate()
	CheckDate(cert_name, *not_before)

}

// Обновляем сертификат
func loadNewCert() error {
	//line := fmt.Sprintf("/opt/naumen/java/bin/keytool -import -alias cert%d -file %s -keystore /opt/naumen/svcNaumenADM/conf/naumen.keystore -storepass %s", time.Now().Year(), fileName, keystore)
	//line := fmt.Sprintf("/usr/bin/keytool -import -noprompt -alias cert%d -file %s -keystore /home/marchenko/.keystore -storepass %s", time.Now().Year(), fileName, keystore)
	cmd := exec.Command(
		"/opt/naumen/java/bin/keytool",
		"-import",
		"-noprompt",
		"-alias",
		fmt.Sprintf("cert%d", time.Now().Year()),
		"-file",
		fileName,
		"-keystore",
		"/opt/naumen/svcNaumenADM/conf/naumen.keystore",
		"-storepass",
		keystore,
	)
	fmt.Println(cmd)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	return nil
}

// Парсим конфиг файл
func ParseConfig(path string) {
	p, err := configparser.NewConfigParserFromFile(path)
	if err != nil {
		conf, err := os.Create(path)
		if err != nil {
			log.Fatal("Не конфигурационного файла! При попытке создания config.cfg произошла ошибка\n", err)
		}
		data := `[Email]
sender =
passwd =
server =
port = 
recepient = 
keystore = `
		conf.Write([]byte(data))
		defer conf.Close()
		log.Fatal("Новый конфигурационный файл создан - config.cfg, заполните значения")
	}
	email, err = p.Get("Email", "sender")
	if err != nil {
		log.Fatal(err)
	}
	email = strings.TrimSpace(email)
	passwd, err = p.Get("Email", "passwd")
	if err != nil {
		log.Fatal(err)
	}
	passwd = strings.TrimSpace(passwd)
	server, err = p.Get("Email", "server")
	if err != nil {
		log.Fatal(err)
	}
	server = strings.TrimSpace(server)
	port, err = p.Get("Email", "port")
	if err != nil {
		log.Fatal(err)
	}
	port = strings.TrimSpace(port)
	rec, err := p.Get("Email", "recepient")
	if err != nil {
		log.Fatal(err)
	} else {
		tmp := strings.Split(rec, ",")
		if len(tmp) == 0 {
			log.Fatal("Не заполнено поле recepient в конфиг файле")
		} else {
			for _, line := range tmp {
				recepient = append(recepient, strings.TrimSpace(line))
			}
		}
	}
	keystore, err = p.Get("Email", "keystore")
	if err != nil {
		log.Fatal(err)
	}
	keystore = strings.TrimSpace(keystore)

	if len(email) == 0 || len(passwd) == 0 || len(server) == 0 || len(port) == 0 || len(recepient) == 0 || len(keystore) == 0 {
		log.Fatal("Не заполнены все поля в конфигурационном файле!")
	}
}

// Отправляем уведомление о том, что сертификат изменился
func SendMailNotification(date, msg string) error {
	var body string
	subject := "Subject: Сертификат Naumen\r\n\r\n"
	if len(msg) != 0 {
		body += msg
	} else {
		body += fmt.Sprintf("Обновился сертификат, актуальная дата: %s", date)
	}
	message := []byte(subject + body)
	auth := smtp.PlainAuth("", email, passwd, server)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         server,
	}
	conn, err := tls.Dial("tcp", server+":"+port, tlsconfig)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, server)
	if err != nil {
		return err
	}
	if err = c.Auth(auth); err != nil {
		return err
	}
	if err = c.Mail(email); err != nil {
		return err
	}
	for _, recepient := range recepient {
		if err = c.Rcpt(recepient); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(message)
	if err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	c.Quit()
	return nil
}

// Получаем текущую дату выпуска сертификата и сохраняем в файл
func GetCertDate() (*time.Time, string) {
	url := "https://fcm.googleapis.com/fcm/send"
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	var not_before time.Time
	//var new_cert x509.Certificate
	var new_cert bytes.Buffer
	cert_name := "edgecert.googleapis.com"
	certs := response.TLS.PeerCertificates
	var b bytes.Buffer
	for _, cert := range certs {
		err = pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(cert.Subject)
		if cert.Subject.CommonName == cert_name {
			not_before = cert.NotBefore
			new_cert = b
		}
	}
	if _, err = os.Stat(folder); os.IsNotExist(err) {
		err = os.Mkdir(folder, 0744)
		if err != nil {
			log.Fatal(err)
		}
	}
	if _, err = os.Stat(fileName); os.IsNotExist(err) {
		err = ioutil.WriteFile(fileName, new_cert.Bytes(), 0744)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		err = os.Remove(fileName)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(fileName, new_cert.Bytes(), 0744)
		if err != nil {
			log.Fatal(err)
		}
	}
	return &not_before, cert_name
}

// Создание подключения к БД
// База будет храниться рядом с исходником
func WriteToDB(name string, date time.Time) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	//Создаем таблицу
	_, _ = db.Exec("CREATE TABLE certs(id INTEGER PRIMARY KEY, name TEXT, date TEXT);")
	rows, err := db.Query("SELECT * FROM certs;")
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()

	if !rows.Next() {
		//Вставляем значения
		query := fmt.Sprintf("INSERT INTO certs(name, date) VALUES(\"%s\", \"%s\");", name, date)
		//fmt.Println(query)
		_, err = db.Exec(query)
		if err != nil {
			log.Fatal(err)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

// Проверяем дату выпуска сертификата с той, которая храниться в БД
func CheckDate(name string, d time.Time) {

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM certs WHERE name LIKE \"%s\";", name)
	rows, err := db.Query(query)
	if err != nil {
		fmt.Println(err)
		if err = loadNewCert(); err != nil {
			fmt.Println("Не удалось обновить сертификат!", err)
			if err = SendMailNotification(d.String(), fmt.Sprintf("Не удалось обновить сертификат! %s", err)); err != nil {
				log.Fatal("Отправить сообщение не удалось! ", err)
			}
		} else {
			WriteToDB(name, d)
		}
	} else {
		for rows.Next() {
			var (
				id   int
				name string
				date string
			)
			if err = rows.Scan(&id, &name, &date); err != nil {
				log.Fatal(err)
			}
			t := fmt.Sprintf("%s", d)
			if date != t {
				if err = loadNewCert(); err != nil {
					fmt.Println("Дата выпуска сертификата изменилась, но обновить сертификат не удалось!", err)
					if err = SendMailNotification(d.String(), fmt.Sprintf("Дата выпуска сертификата изменилась, но обновить сертификат не удалось! %s", err)); err != nil {
						fmt.Println("Отправить сообщение не удалось", err)
					}
				} else {
					if err = SendMailNotification(t, ""); err != nil {
						log.Fatal("Сертификат обновлен! Требуется перезагрузка. Отправка уведомления не удалось. ", err)
					}
					deletePrevValue(name)
					WriteToDB(name, d)
				}
			} else {
				fmt.Fprintf(os.Stdout, "На текущий момент установлена актуальная версия сертификата: %s %s\n", name, date)
			}
		}
	}
}

// Удаляем предыдущую запись в БД
func deletePrevValue(name string) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := fmt.Sprintf("DELETE FROM certs WHERE name LIKE \"%s\";", name)
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
}
