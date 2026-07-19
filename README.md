# 🔐 Web Simulasi Algoritma Kriptografi

> **UAS Mata Kuliah Kriptografi**
> Semester 6 • Tahun Akademik 2025/2026

Aplikasi ini merupakan media pembelajaran berbasis web yang dirancang untuk membantu pengguna memahami proses kerja algoritma kriptografi simetris secara interaktif. Berbeda dengan aplikasi enkripsi biasa yang hanya menampilkan hasil akhir, aplikasi ini memperlihatkan setiap tahapan proses enkripsi maupun dekripsi secara rinci (step-by-step), sehingga pengguna dapat mengikuti transformasi data dari awal hingga akhir.

Aplikasi mengimplementasikan empat algoritma kriptografi simetris, yaitu **Data Encryption Standard (DES)**, **Simplified Data Encryption Standard (S-DES)**, **Advanced Encryption Standard (AES-128)**, dan **Simplified Advanced Encryption Standard (S-AES)**. Seluruh algoritma diimplementasikan secara manual menggunakan Python tanpa memanfaatkan library kriptografi eksternal, sehingga setiap proses dapat divisualisasikan sesuai dengan teori yang dipelajari pada mata kuliah Kriptografi.

---

# 📌 Latar Belakang

Kriptografi merupakan salah satu bidang penting dalam keamanan informasi yang bertujuan menjaga kerahasiaan, integritas, dan keaslian data melalui proses enkripsi dan dekripsi. Dalam proses pembelajaran, mahasiswa sering mengalami kesulitan memahami bagaimana setiap algoritma kriptografi bekerja secara internal karena sebagian besar implementasi yang tersedia hanya menampilkan hasil akhir tanpa menjelaskan proses komputasinya.

Sebagai solusi, dikembangkan sebuah aplikasi web simulasi yang mampu memperlihatkan setiap tahapan algoritma secara visual. Pengguna dapat memasukkan plaintext, ciphertext, maupun kunci, kemudian melihat proses pembentukan subkey, transformasi state, operasi substitusi, permutasi, XOR, hingga menghasilkan ciphertext atau plaintext.

Aplikasi ini dikembangkan sebagai pemenuhan tugas UAS Mata Kuliah Kriptografi sekaligus sebagai media pembelajaran yang dapat digunakan untuk memverifikasi hasil perhitungan manual sesuai dengan spesifikasi tugas.

---

# 🧠 Deskripsi Aplikasi

Aplikasi ini dibangun menggunakan framework **Flask** dengan bahasa pemrograman Python sebagai backend serta HTML, CSS, JavaScript, Bootstrap, dan Jinja2 sebagai frontend. Seluruh modul algoritma ditempatkan dalam satu landing page sehingga pengguna dapat berpindah antar algoritma melalui menu navigasi.

Setiap modul menyediakan dua mode operasi, yaitu **Encrypt** dan **Decrypt**, dilengkapi dengan form input, validasi data, tombol submit, tombol reset, hasil akhir, serta panel "Tampilkan Solusi Penyelesaian" yang memuat seluruh tahapan algoritma secara rinci.

Selain menghasilkan ciphertext maupun plaintext, aplikasi juga memvisualisasikan pembentukan subkey atau round key, proses transformasi pada setiap ronde, serta perubahan state pada setiap langkah sehingga hasil aplikasi dapat dibandingkan secara langsung dengan perhitungan manual.

---

# ✨ Fitur Utama

## Landing Page

* Tampilan modern dan responsif
* Navigasi menuju modul DES, S-DES, AES, dan S-AES
* Penjelasan singkat mengenai setiap algoritma
* Responsif pada desktop maupun perangkat mobile

## Modul DES

* Input plaintext/ciphertext 64-bit
* Input key 64-bit
* Mode Encrypt dan Decrypt
* Generate 16 subkey
* PC-1
* Left Shift
* PC-2
* Initial Permutation
* Expansion Permutation
* XOR
* S-Box
* P-Box
* Swap
* Final Permutation
* Step-by-Step Solution

## Modul S-DES

* Input plaintext 8-bit
* Input key 10-bit
* Encrypt dan Decrypt
* Generate K1 dan K2
* P10
* LS-1
* LS-2
* P8
* Initial Permutation
* Round Function
* Swap
* Final Permutation
* Detail proses

## Modul AES-128

* Input plaintext 128-bit
* Input key 128-bit
* Encrypt dan Decrypt
* Key Expansion
* RotWord
* SubWord
* Rcon
* AddRoundKey
* SubBytes
* ShiftRows
* MixColumns
* Final Round
* State Matrix 4×4

## Modul S-AES

* Input plaintext 16-bit
* Input key 16-bit
* Encrypt dan Decrypt
* RotNib
* SubNib
* Rcon
* Key Expansion
* Round Key K0–K2
* ShiftRows
* MixColumns
* AddRoundKey
* State Matrix 2×2

---

# 🛠️ Teknologi yang Digunakan

## Backend

* Python 3.x
* Flask

## Frontend

* HTML5
* CSS3
* Bootstrap 5
* JavaScript
* Jinja2

## Tools

* Visual Studio Code
* Git
* GitHub
* Vercel (Deployment)

## Implementasi

* Tidak menggunakan library kriptografi eksternal.
* Seluruh algoritma DES, S-DES, AES, dan S-AES diimplementasikan secara manual berdasarkan spesifikasi algoritma.

---

# 🧩 Struktur Proyek

```text
crypto-web/
│
├── algorithms/
│   ├── des.py
│   ├── sdes.py
│   ├── aes.py
│   ├── saes.py
│   ├── gf.py
│   ├── sbox.py
│   ├── helpers.py
│   └── ...
│
├── templates/
│   ├── index.html
│   ├── des.html
│   ├── sdes.html
│   ├── aes.html
│   └── saes.html
│
├── static/
│   ├── css/
│   └── js/
│
├── app.py
├── requirements.txt
├── vercel.json
├── README.md
└── .gitignore
```

---

# 🚀 Cara Menjalankan Lokal

1. Clone repository

```bash
git clone https://github.com/USERNAME/crypto-web.git
```

2. Masuk ke folder project

```bash
cd crypto-web
```

3. Buat virtual environment

```bash
python -m venv venv
```

4. Aktifkan virtual environment

Windows

```cmd
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

5. Install dependency

```bash
pip install -r requirements.txt
```

6. Jalankan aplikasi

```bash
python app.py
```

7. Buka browser

```text
http://127.0.0.1:5000
```

---

# 🧪 Contoh Uji (Test Vector)

Gunakan contoh berikut untuk memverifikasi implementasi algoritma pada aplikasi.

## DES

* Plaintext : `0123456789ABCDEF`
* Key : `133457799BBCDFF1`

## S-DES

* Plaintext : `10101010`
* Key : `1010000010`

## AES-128

* Plaintext : `00112233445566778899AABBCCDDEEFF`
* Key : `000102030405060708090A0B0C0D0E0F`

## S-AES

* Plaintext : `0110111101101011`
* Key : `1010011100111011`

---

# 🧠 Kesesuaian dengan Spesifikasi

Aplikasi telah dikembangkan sesuai dengan spesifikasi UAS Mata Kuliah Kriptografi.

* ✅ Landing Page
* ✅ Empat modul algoritma
* ✅ Encrypt & Decrypt
* ✅ Input plaintext/ciphertext dan key
* ✅ Tombol Submit
* ✅ Tombol Reset
* ✅ Hasil akhir
* ✅ Tampilkan solusi penyelesaian
* ✅ Step-by-Step Process
* ✅ Implementasi manual tanpa library kriptografi
* ✅ Responsive User Interface

---

# 🔐 Penjelasan Proses Kriptografi Simetris (DES, S-DES, AES, S-AES) yang Ditampilkan

## DES

Modul DES memperlihatkan proses pembentukan 16 subkey menggunakan PC-1, Left Shift, dan PC-2. Selanjutnya dilakukan Initial Permutation, 16 ronde Feistel yang terdiri atas Expansion Permutation, XOR dengan subkey, substitusi menggunakan delapan S-Box, permutasi P, dan pertukaran blok kiri-kanan sebelum menghasilkan ciphertext melalui Final Permutation.

## S-DES

Modul S-DES memvisualisasikan pembentukan K1 dan K2 menggunakan P10, Left Shift, dan P8. Selanjutnya ditampilkan Initial Permutation, dua ronde fungsi Feistel, proses Swap, serta Inverse Initial Permutation hingga menghasilkan ciphertext maupun plaintext.

## AES-128

Pada modul AES ditampilkan proses Key Expansion menggunakan RotWord, SubWord, dan Rcon untuk menghasilkan sebelas round key. Seluruh ronde enkripsi memperlihatkan perubahan state matrix 4×4 melalui SubBytes, ShiftRows, MixColumns, dan AddRoundKey. Ronde terakhir dijalankan tanpa MixColumns sesuai standar AES-128.

## S-AES

Modul S-AES menampilkan proses pembentukan round key K0, K1, dan K2 menggunakan RotNib, SubNib, dan Rcon. Selanjutnya divisualisasikan Initial Round, Round 1 (SubNib, ShiftRows, MixColumns, AddRoundKey), serta Round 2 (SubNib, ShiftRows, AddRoundKey) sehingga pengguna dapat mengikuti perubahan state matrix 2×2 pada setiap langkah.

---

# ☁️ Deploy ke Vercel (Opsional)

1. Push project ke GitHub.
2. Login ke Vercel.
3. Import repository dari GitHub.
4. Pilih framework **Other**.
5. Pastikan file `requirements.txt` dan `vercel.json` telah dikonfigurasi.
6. Lakukan proses deployment hingga aplikasi dapat diakses secara publik.

---

# 📁 Penjelasan File Utama

| File/Folder          | Deskripsi                                          |
| -------------------- | -------------------------------------------------- |
| `app.py`             | Route utama aplikasi Flask dan pengaturan navigasi |
| `algorithms/des.py`  | Implementasi algoritma DES                         |
| `algorithms/sdes.py` | Implementasi algoritma S-DES                       |
| `algorithms/aes.py`  | Implementasi algoritma AES-128                     |
| `algorithms/saes.py` | Implementasi algoritma S-AES                       |
| `templates/`         | Halaman HTML untuk setiap modul                    |
| `static/css/`        | Stylesheet aplikasi                                |
| `static/js/`         | JavaScript interaktif                              |
| `requirements.txt`   | Daftar dependency Python                           |
| `vercel.json`        | Konfigurasi deployment Vercel                      |
| `.gitignore`         | Daftar file yang diabaikan Git                     |
| `README.md`          | Dokumentasi project                                |

---

# 👤 Identitas Tugas

| Keterangan         | Isi                                |
| ------------------ | ---------------------------------- |
| Mata Kuliah        | Kriptografi                        |
| Tugas              | Ujian Akhir Semester (UAS)         |
| Pembuat            | Purnamasari Siregar                |
| Semester           | 6                                  |
| Tahun Akademik     | 2025/2026                          |
