# 🔐 CryptoVault

**CryptoVault** — консольная утилита для управления паролями, которая использует базовые методы криптографии для обеспечения надежного хранения данных.


## Криптографические принципы.

- **Key Derivation Function (Производный ключ)**: функция `PBKDF2`, которая многократно хэширует пароль и создает криптографически безопасный ключ для защиты от brute-force атак и rainbow tables атак.
- **AES Шифрование**: режим `AES-GCM`, который обеспечивает конфиденциальность и аутентификацию (проверка подлинности).
- **Контроль целостности**: проверка `HMAC-SHA256` обеспечивает защиту от подмен.
- **Sault**: генерация уникального значения `salt` при каждом запуске, что обеспечивает дополнительную безопасность, т.к. хранилище будет уникальным даже при использовании одинаковых паролей.


Все данные сохраняются в `vault.json` только в зашифрованном виде.


---

Приме содержимого хранилища из файла `vault.json`:
```json
{
  "salt": "ybs6Me0Xy6PviA8qQmaWrw==",
  "entries": {
    "Telegram": {
      "nonce": "Xq12L9eqVHGWI2uo",
      "ct": "MMe9IKaVL9E9NqVAXlTZtDoIg/b6",
      "tag": "EZPqcZu/yZ8ObqLtGtXVoQ==",
      "hmac": "8+dNrSk2yGaqrfQFSCfKupYUItUJGncZ4/IG8OAAfOU="
    }
  }
}
```




## Установка
```bash
git clone https://github.com/inno1314/CryptoVault.git
cd CryptoVault

python3 -m venv .venv
source .venv/bin/activate

pip3 install -r requirements.txt
```
## Примеры использования
Добавление записи:
```bash
python3 -m app.main --add Telegram
Creating a new vault...
Enter passphrase: 
Enter password to store: 
Entry 'Telegram' added.
```
Просмотр списка записей:
```bash
python3 -m app.main --list
Enter passphrase: 
Stored entries:
- Telegram
```
Получение пароля:
```bash
python3 -m app.main --get Telegram
Enter passphrase: 
Telegram: mystrong#password1314
```
Ошибка при использовании неправильного мастер-ключа:
```bash
python3 -m app.main --get Telegram
Enter passphrase: 
Ошибка дешифровки: Ошибка проверки HMAC.
```
