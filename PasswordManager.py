import hashlib
import os
import json
from logging import exception
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from datetime import datetime
import random
import string
import re
import shutil


FILE_NAME = "./Records/records.json"
BACKUP_FILE_NAME = "./Records/records_backup.json"
LOG_FILE_NAME = "./Logs/change_log.txt"


class PasswordAnalysisSystem:
    def __init__(self):
        self.default_policy = {
            "min_length": 8,
            "max_length": 99,
            "require_uppercase": False,
            "require_lowercase": True,
            "require_digit": True,
            "require_symbol": False
        }
        self.char_sets = {
            "lowercase": string.ascii_lowercase,
            "uppercase": string.ascii_uppercase,
            "digits": string.digits,
            "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?"
        }

    def generate_password(self, length: int = 12,
                          use_lowercase: bool = True,
                          use_uppercase: bool = True,
                          use_digits: bool = True,
                          use_symbols: bool = False):

        if length < self.default_policy.get("min_length", 8):
            print(f"Попередження: Бажана довжина пароля ({length}) менша за мінімально дозволену політикою "
                  f"({self.default_policy['min_length']}). Встановлено довжину {self.default_policy['min_length']}.")

            length = self.default_policy["min_length"]
        length = min(length, self.default_policy.get("max_length", 99))

        character_pool = []
        if use_lowercase:
            character_pool.extend(list(self.char_sets["lowercase"]))
        if use_uppercase:
            character_pool.extend(list(self.char_sets["uppercase"]))
        if use_digits:
            character_pool.extend(list(self.char_sets["digits"]))
        if use_symbols:
            character_pool.extend(list(self.char_sets["symbols"]))

        if not character_pool:
            print("Помилка: не обрано жодного набору символів для генерації пароля.")
            return None
        try:
            password_list = random.choices(character_pool, k=length)
        except AttributeError:
            password_list = [random.choice(character_pool) for _ in range(length)]
        random.shuffle(password_list)
        return "".join(password_list)

    def check_policy(self, password: str, policy: dict = None) -> tuple[bool, list[str]]:
        if policy is None:
            policy = self.default_policy
        errors = []
        if policy.get("require_uppercase") and not re.search(r"[A-Z]", password):
            errors.append("Пароль має містити принаймні одну велику літеру (згідно поточної політики).")
        if policy.get("require_lowercase") and not re.search(r"[a-z]", password):
            errors.append("Пароль має містити принаймні одну малу літеру.")
        if policy.get("require_digit") and not re.search(r"\d", password):
            errors.append("Пароль має містити принаймні одну цифру.")
        if policy.get("require_symbol") and self.char_sets["symbols"] and \
                not re.search(rf"[{re.escape(self.char_sets['symbols'])}]", password):
            errors.append(f"Пароль має містити принаймні один спецсимвол ({self.char_sets['symbols']}).")
        return not errors, errors

    def assess_strength(self, password: str) -> str:
        length = len(password)
        score = 0
        if length >= self.default_policy.get("min_length", 8):
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if self.char_sets["symbols"] and re.search(rf"[{re.escape(self.char_sets['symbols'])}]", password):
            score += 1
        if len(set(password)) >= length * 0.7 and length > 0:
            score += 1
        if score <= 2:
            return "Дуже слабкий"
        if score <= 4:
            return "Слабкий"
        if score <= 6:
            return "Середній"
        if score <= 7:
            return "Сильний"
        return "Дуже сильний"

    def is_password_reused(self, new_password: str, records_map: dict,
                           current_site: str | None = None,
                           current_login: str | None = None) -> bool:
        for site_name, entries in records_map.items():
            for entry in entries:
                if site_name == current_site and entry.get("login") == current_login:
                    continue
                if entry.get("password") == new_password:
                    print(
                        f"ПОПЕРЕДЖЕННЯ: Цей пароль вже використовується для сайту '{site_name}', "
                        f"логін '{entry.get('login')}'!")
                    return True
        return False

    def password_creating(self,
                          records_map_for_reuse_check: dict,
                          prompt_message: str = "Пароль",
                          current_site_for_reuse: str | None = None,
                          current_login_for_reuse: str | None = None,
                          allow_empty_for_no_change: bool = False
                          ) -> str | None:

        password_value = None
        policy = self.default_policy
        password_min_len = policy["min_length"]
        password_max_len = policy["max_length"]

        print(f"\n--- {prompt_message} ---")
        pass_choice_prompt = "Згенерувати автоматично (1), ввести вручну (2)"
        if allow_empty_for_no_change:
            pass_choice_prompt += " (або Enter, щоб не змінювати)?"
        else:
            pass_choice_prompt += " (або Enter для скасування)?"

        pass_choice = input(f"{pass_choice_prompt}: ").strip()
        if pass_choice == "1":
            print("\n--- Опції генерації пароля ---")
            try:
                length = int(input(
                    f"Бажана довжина (мін: {policy['min_length']}, макс: {policy['max_length']}, "
                    f"рек: 12-16): ").strip())
                if not (policy['min_length'] <= length <= policy['max_length']):
                    length = 12
                    print(f"Встановлено довжину за замовчуванням: {length}.")
            except ValueError:
                length = 12
                print(f"Некоректна довжина. Встановлено за замовчуванням: {length}.")

            use_lower = input("Малі літери (a-z)? (так/ні, Enter - так): ").lower() != 'ні'
            use_upper = input("Великі літери (A-Z)? (так/ні, Enter - так): ").lower() != 'ні'
            use_digits = input("Цифри (0-9)? (так/ні, Enter - так): ").lower() != 'ні'
            use_symbols = input(f"Спецсимволи ({self.char_sets['symbols']})? (так/ні, Enter - так): ").lower() != 'ні'

            if not (use_lower or use_upper or use_digits or use_symbols):
                print("Не обрано жодного типу символів. Буде використано стандартний набір (малі+великі+цифри).")
                use_lower, use_upper, use_digits = True, True, True

            generated_password = self.generate_password(length, use_lower, use_upper, use_digits, use_symbols)
            if generated_password is None:
                print("Не вдалося згенерувати пароль.")
                return None

            print(f"Згенеровано пароль: {generated_password}")
            print(f"Надійність: {self.assess_strength(generated_password)}")
            if self.is_password_reused(generated_password, records_map_for_reuse_check, current_site_for_reuse,
                                       current_login_for_reuse):
                if input("Згенерований пароль вже використовується. "
                         "Все одно продовжити? (1).так (2).ні: ").lower() != '1':
                    return None
            password_value = generated_password

        elif pass_choice == "2":
            attempts = 0
            while attempts < 3:
                user_input_pass = input(f"Введіть пароль (довжина: {password_min_len}-{password_max_len} симв.): ")

                input_length = len(user_input_pass)
                if not (password_min_len <= input_length <= password_max_len):
                    print(f"Довжина пароля має бути від {password_min_len} до {password_max_len} символів.")
                    attempts += 1
                    print(f"Залишилося спроб: {3 - attempts}")
                    continue

                is_valid_policy, errors = self.check_policy(user_input_pass, policy)
                if is_valid_policy:
                    print(f"Надійність пароля: {self.assess_strength(user_input_pass)}")
                    if self.is_password_reused(user_input_pass, records_map_for_reuse_check, current_site_for_reuse,
                                               current_login_for_reuse):
                        if input("Цей пароль вже використовується. "
                                 "Зберегти? ((1).так (2).ні: ").lower() != '1':
                            # print(f"Залишилося спроб: {3 - attempts}")
                            continue
                    password_value = user_input_pass
                    break
                else:
                    print("Пароль не відповідає політиці безпеки:")
                    for error in errors:
                        print(f" - {error}")
                attempts += 1
                print(f"Залишилося спроб: {3 - attempts}")
            if not password_value:
                print("Вичерпано спроби для введення пароля.")

        elif pass_choice == "" and allow_empty_for_no_change:
            return ""
        elif pass_choice == "" and not allow_empty_for_no_change:
            print("Отримання пароля скасовано.")
            return None
        else:
            print("Невірний вибір.")
            return None

        return password_value


class SecuritySystem:
    def __init__(self):
        pass

    def encode_password(self, password: str) -> str:
        password_bytes = password.encode('utf-8')
        hashed_password = hashlib.sha256(password_bytes).hexdigest()
        return hashed_password

    def get_encryption_key(self, master_password: str) -> bytes:
        return hashlib.sha256(master_password.encode('utf-8')).digest()

    def get_stored_hash(self):
        if not os.path.exists(FILE_NAME):
            print(f"Файл '{FILE_NAME}' не знайдено.")
            return None
        try:
            with open(FILE_NAME, 'r') as records_file:
                if os.path.getsize(FILE_NAME) == 0:
                    print(f"Файл '{FILE_NAME}' порожній.")
                    return None

                data = json.load(records_file)
                return data.get("hash_master_password")
        except Exception as e:
            print(f"Невідома помилка при завантаженні хешу: {e}")
            return None

    def verify_password(self, entered_password: str) -> bool:
        stored_hash = self.get_stored_hash()
        if stored_hash is None:
            return False

        entered_hash = self.encode_password(entered_password)
        return True if entered_hash == stored_hash else False

    def encrypt_data(self, records_dict_to_encrypt: dict, key: bytes):
        try:
            plaintext_json_string = json.dumps(records_dict_to_encrypt)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            data_bytes = plaintext_json_string.encode('utf-8')
            ciphertext_bytes = aesgcm.encrypt(nonce, data_bytes, None)
            return base64.b64encode(nonce + ciphertext_bytes).decode('utf-8')
        except Exception as e:
            print(f"Помилка шифрування даних: {e}")
            return None

    def decrypt_data(self, encrypted_records_blob_base64: str, key: bytes):
        try:
            encrypted_blob_bytes = base64.b64decode(encrypted_records_blob_base64.encode('utf-8'))
            nonce = encrypted_blob_bytes[:12]
            ciphertext_bytes = encrypted_blob_bytes[12:]
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, None)
            return json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            print(f"Помилка дешифрування даних: {e}")
            return None

    def decrypt_records_in_file_on_disk(self, master_password: str) -> bool:
        if not os.path.exists(FILE_NAME):
            print(f"Файл '{FILE_NAME}' не знайдено для розшифрування.")
            return False

        key = self.get_encryption_key(master_password)
        try:
            with open(FILE_NAME, 'r') as f_read:
                if os.path.getsize(FILE_NAME) == 0:
                    print(f"Файл '{FILE_NAME}' порожній.")
                    return False
                full_file_data = json.load(f_read)

            stored_hash = full_file_data.get("hash_master_password")
            encrypted_content_blob = full_file_data.get("encrypted_content")

            if stored_hash is None:
                print("Помилка: відсутній хеш майстер-пароля у файлі.")
                return False

            if encrypted_content_blob is None:
                if "records" in full_file_data:
                    print(f"Записи у файлі '{FILE_NAME}' вже розшифровано.")
                    return True
                return False

            decrypted_records_structure = self.decrypt_data(encrypted_content_blob, key)
            if decrypted_records_structure is None:
                print("Не вдалося розшифрувати записи.")
                return False

            data_to_write_decrypted = {
                "hash_master_password": stored_hash,
                "records": decrypted_records_structure.get("records", {})
            }
            with open(FILE_NAME, 'w') as f_write:
                json.dump(data_to_write_decrypted, f_write, indent=4)
            return True
        except Exception as e:
            print(f"Помилка під час розшифрування записів у файлі: {e}")
            return False

    def encrypt_records_in_file_on_disk(self, master_password: str) -> bool:
        if not os.path.exists(FILE_NAME):
            print(f"Файл '{FILE_NAME}' не знайдено для шифрування.")
            return False

        key = self.get_encryption_key(master_password)
        try:
            with open(FILE_NAME, 'r') as f_read:
                if os.path.getsize(FILE_NAME) == 0:
                    print(f"Файл '{FILE_NAME}' порожній, нічого шифрувати.")
                    return False
                full_file_data = json.load(f_read)

            stored_hash = full_file_data.get("hash_master_password")
            plaintext_records_field = full_file_data.get("records")

            if stored_hash is None:
                print("Помилка: відсутній хеш майстер-пароля у файлі для збереження зашифрованих даних.")
                return False

            records_structure_to_encrypt = {"records": plaintext_records_field}
            encrypted_content_blob = self.encrypt_data(records_structure_to_encrypt, key)

            if encrypted_content_blob is None:
                return False

            data_to_write_encrypted = {
                "hash_master_password": stored_hash,
                "encrypted_content": encrypted_content_blob
            }
            with open(FILE_NAME, 'w') as f_write:
                json.dump(data_to_write_encrypted, f_write, indent=4)
            print(f"Записи у файлі '{FILE_NAME}' успішно зашифровано.")
            return True
        except Exception as e:
            print(f"Загальна помилка під час шифрування записів у файлі: {e}")
            return False

    def write_encrypted_data_to_backup_file(self, master_password: str,
                                            plaintext_data_to_backup: dict,
                                            backup_file_path: str) -> bool:

        try:
            original_hash = plaintext_data_to_backup.get("hash_master_password")
            records_content_to_encrypt = plaintext_data_to_backup.get("records", {})

            if original_hash is None:
                print("Помилка (SecuritySystem): 'hash_master_password' відсутній у даних для резервної копії.")
                original_hash = self.encode_password(master_password)

            encryption_key = self.get_encryption_key(master_password)
            encrypted_blob = self.encrypt_data({"records": records_content_to_encrypt},
                                               encryption_key)

            if encrypted_blob is None:
                print("Не вдалося зашифрувати дані для резервної копії.")
                return False

            backup_structure_to_write = {
                "hash_master_password": original_hash,
                "encrypted_content": encrypted_blob
            }

            with open(backup_file_path, 'w') as backup_f:
                json.dump(backup_structure_to_write, backup_f, indent=4)
            print(f"Зашифровану резервну копію успішно створено у '{backup_file_path}'.")
            return True
        except Exception as e:
            print(f"Помилка під час шифрування та запису резервної копії: {e}")
            return False


class AutocompleteSystem:
    def suggest_platforms(self, partial_platform_name: str, existing_records_map: dict):
        if not partial_platform_name:
            return []

        unique_platform_names = set()
        for platform_name in existing_records_map.keys():
            if platform_name.lower().startswith(partial_platform_name.lower()):
                unique_platform_names.add(platform_name)
        suggestions = sorted(list(unique_platform_names))
        return suggestions

    def suggest_logins_globally(self, partial_login: str, existing_records_map: dict):
        if not partial_login:
            return []

        unique_logins = set()
        for platform_name, entries in existing_records_map.items():
            for entry in entries:
                login = entry.get("login")
                if login and login.lower().startswith(partial_login.lower()):
                    unique_logins.add(login)
        return sorted(list(unique_logins))


class RecordManagementSystem:
    def __init__(self, file_path: str, security_system_instance: SecuritySystem):
        self.file_path = file_path
        self.password_analyzer = PasswordAnalysisSystem()
        self.autocomplete_system = AutocompleteSystem()
        self.security_system = security_system_instance

    def log_change(self, action_description: str):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"({timestamp}): {action_description}\n"
            with open(LOG_FILE_NAME, 'a', encoding='utf-8') as log_file:
                log_file.write(log_entry)
        except Exception as e:
            print(f"Помилка запису в лог-файл: {e}")

    def load_data_from_file(self):
        if not os.path.exists(self.file_path):
            print(f"Помилка: файл '{self.file_path}' не знайдено.")
            return None
        try:
            with open(self.file_path, 'r') as f:
                if os.path.getsize(self.file_path) == 0:
                    print(f"Попередження: файл '{self.file_path}' порожній.")
                    return None
                data = json.load(f)
            return data
        except Exception as e:
            print(f"Невідома помилка при завантаженні даних з файлу '{self.file_path}': {e}")
            return None

    def save_data_to_file(self, data_to_save: dict) -> bool:
        try:
            with open(self.file_path, 'w') as f:
                json.dump(data_to_save, f, indent=4)
            return True
        except Exception as e:
            print(f"Невідома помилка при збереженні даних у файл '{self.file_path}': {e}")
            return False

    def get_field_with_suggestions(self,
                                   field_prompt_name: str,
                                   current_partial_input: str,
                                   suggestions: list[str],
                                   min_len: int, max_len: int):
        if suggestions:
            print(f"Знайдено збіги для {field_prompt_name}:")
            for i, suggestion in enumerate(suggestions):
                print(f"  {i + 1}. {suggestion}")
            print(
                f"  {len(suggestions) + 1}. Ввести '{current_partial_input}' як нове значення "
                f"(або продовжити введення)")
            print(f"  0. Скасувати введення цього поля / Повернутися")

            choice_str = input("Оберіть номер або введіть повне значення: ").strip()
            try:
                choice_num = int(choice_str)
                if choice_num == 0:
                    return None
                if 1 <= choice_num <= len(suggestions):
                    final_value = suggestions[choice_num - 1]
                    print(f"Обрано: {final_value}")
                elif choice_num == len(suggestions) + 1:
                    if min_len <= len(current_partial_input) <= max_len:
                        final_value = current_partial_input
                    else:
                        print(f"Довжина '{current_partial_input}' не відповідає "
                              f"({min_len}-{max_len}). Введіть повне значення.")
                        final_value = None
                else:
                    print("Невірний вибір.")
                    return "RETRY"
            except ValueError:
                final_value = choice_str
        else:
            final_value = current_partial_input

        if final_value is None or not (min_len <= len(final_value) <= max_len):
            if final_value is not None and final_value != current_partial_input:
                pass
            elif final_value == current_partial_input and not (min_len <= len(final_value) <= max_len) and suggestions:
                print(f"Довжина '{final_value}' не відповідає ({min_len}-{max_len}).")
                pass
            else:
                pass

            attempts = 0
            while attempts < 3:
                prompt = f"Введіть повне значення для '{field_prompt_name}' (довжина: {min_len}-{max_len}): "
                if final_value and not (min_len <= len(final_value) <= max_len):
                    prompt = (f"Введіть коректне значення для '{field_prompt_name}' "
                              f"(поточне: '{final_value}', довжина: {min_len}-{max_len}): ")

                input_val = input(prompt).strip()
                if not input_val and min_len > 0:
                    print(f"{field_prompt_name.capitalize()} не може бути порожнім.")
                elif min_len <= len(input_val) <= max_len:
                    final_value = input_val
                    break
                else:
                    print(f"Невірна довжина. Залишилося спроб: {2 - attempts}")
                attempts += 1
                if attempts == 3:
                    print(f"Вичерпано спроби для '{field_prompt_name}'.")
                    return None
        return final_value

    def create_new_record(self):
        print("\n--- Створення нового запису ---")
        current_file_data = self.load_data_from_file()
        if current_file_data is None:
            print("Не вдалося завантажити поточні дані. Створення запису неможливе.")
            return

        if "records" not in current_file_data or not isinstance(current_file_data.get("records"), dict):
            current_file_data["records"] = {}
        records_map = current_file_data["records"]

        print("\nДля створення запису вам потрібно ввести назву платформи та логін.")
        u_choice = str(input("Продовжити(1), Скасувати(2): "))
        if u_choice == "2":
            print("Створення запису скасовано.")
            return

        platform_name = None
        field_min_len, field_max_len = 1, 50
        while True:
            partial_platform = input(
                f"Введіть назву платформи (частково або повністю, довжина "
                f"{field_min_len}-{field_max_len}, Enter для скасування): ").strip()

            if not partial_platform:
                print("Введення платформи скасовано.")
                return

            platform_suggestions = self.autocomplete_system.suggest_platforms(partial_platform, records_map)

            chosen_value = self.get_field_with_suggestions(
                "платформи", partial_platform, platform_suggestions, field_min_len, field_max_len
            )
            if chosen_value is None:
                print("Введення платформи скасовано.")
                return
            if chosen_value == "RETRY":
                continue

            platform_name = chosen_value
            break

        if not platform_name:
            print("Платформу не введено. Створення запису скасовано.")
            return

        login = None
        field_min_len, field_max_len = 2, 32
        while True:
            partial_login = input(
                f"Введіть логін для '{platform_name}' (частково або повністю, "
                f"довжина {field_min_len}-{field_max_len}, Enter для скасування): ").strip()
            if not partial_login:
                print("Введення логіна скасовано.")
                return

            login_suggestions = self.autocomplete_system.suggest_logins_globally(partial_login, records_map)
            chosen_value = self.get_field_with_suggestions(
                f"логіна для '{platform_name}'", partial_login, login_suggestions, field_min_len, field_max_len
            )
            if chosen_value is None:
                print("Введення логіна скасовано.")
                return

            if chosen_value == "RETRY":
                continue

            login = chosen_value
            break
        if not login:
            print("Логін не введено. Створення запису скасовано.")
            return

        if platform_name in records_map:
            for entry in records_map.get(platform_name, []):
                if entry.get("login") == login:
                    print(f"Помилка: Запис з логіном '{login}' для платформи '{platform_name}' вже існує.")
                    return

        password_value = self.password_analyzer.password_creating(
            records_map_for_reuse_check=records_map,
            prompt_message="Встановлення пароля для нового запису"
        )
        if password_value is None:
            print("Пароль не було встановлено. Створення запису скасовано.")
            return

        data_created = datetime.now().isoformat()
        new_entry_data = {
            "login": login,
            "password": password_value,
            "data_created": data_created,
            "last_modified": data_created
        }
        records_map.setdefault(platform_name, []).append(new_entry_data)
        if self.save_data_to_file(current_file_data):
            print("Запис успішно створено та збережено у файл.")
            self.log_change(f"Створено запис для платформи '{platform_name}', логін '{login}'.")
        else:
            print("Помилка при збереженні нового запису у файл.")

    def edit_record(self):
        print("\n--- Редагування запису ---")
        current_file_data = self.load_data_from_file()
        if current_file_data is None:
            return

        if "records" not in current_file_data or not isinstance(current_file_data.get("records"), dict):
            current_file_data["records"] = {}
        records_map = current_file_data["records"]

        selection_result = self.select_account(current_file_data)
        if not selection_result:
            return

        original_platform_name, account_idx_to_edit = selection_result
        record_to_edit_original_data = dict(records_map[original_platform_name][account_idx_to_edit])
        original_login_for_log = str(record_to_edit_original_data.get("login", ""))
        original_password_value = record_to_edit_original_data.get("password")

        print(f"\nРедагування запису для '{original_platform_name}': Логін='{original_login_for_log}'")

        new_platform_name = original_platform_name
        change_platform_choice = input(
            f"Поточна платформа: '{original_platform_name}'. Змінити платформу? (1).так (2).ні (Enter) - ні: ").lower()
        if change_platform_choice == '1':
            field_min_len, field_max_len = 1, 50
            temp_platform_name = None
            while True:
                partial_platform = input(
                    f"Введіть нову назву платформи (частково або повністю, "
                    f"довжина {field_min_len}-{field_max_len}, Enter для скасування зміни платформи): ").strip()
                if not partial_platform:
                    print("Зміна платформи скасована, залишено стару.")
                    temp_platform_name = original_platform_name
                    break

                platform_suggestions = self.autocomplete_system.suggest_platforms(partial_platform, records_map)

                chosen_value = self.get_field_with_suggestions(
                    "нової платформи", partial_platform, platform_suggestions, field_min_len,
                    field_max_len
                )

                if chosen_value is None:
                    print("Зміна платформи скасована.")
                    temp_platform_name = original_platform_name
                    break

                if chosen_value == "RETRY":
                    continue

                temp_platform_name = chosen_value
                break
            new_platform_name = temp_platform_name

        new_login = original_login_for_log
        login_policy = {"min_len": 2, "max_len": 32}
        login_attempts = 0
        while login_attempts < 3:
            user_input_login = input(
                f"Новий логін для платформи '{new_platform_name}' "
                f"(довжина {login_policy['min_len']}-{login_policy['max_len']}, "
                f"Enter, щоб залишити '{new_login}'): ")
            if not user_input_login:
                break

            if login_policy['min_len'] <= len(user_input_login) <= login_policy['max_len']:
                if user_input_login != new_login or new_platform_name != original_platform_name:
                    is_duplicate = False
                    for i, entry in enumerate(records_map.get(new_platform_name, [])):
                        is_current_record_being_edited = (
                                    new_platform_name == original_platform_name and i == account_idx_to_edit)
                        if not is_current_record_being_edited and entry.get("login") == user_input_login:
                            is_duplicate = True
                            break
                    if is_duplicate:
                        print(f"Логін '{user_input_login}' вже існує для платформи '{new_platform_name}'.")
                        login_attempts += 1
                        if login_attempts == 3:
                            print("Вичерпано спроби. Поточний логін не змінено.")
                            break
                        continue
                new_login = user_input_login
                break
            else:
                print(f"Невірна довжина. Залишилося спроб: {2 - login_attempts}")
            login_attempts += 1
            if login_attempts == 3:
                print("Вичерпано спроби. Поточний логін не змінено.")
                break

        print(f"\nПоточний пароль для '{new_login}' на '{new_platform_name}': '*******' (приховано)")
        new_password_value = self.password_analyzer.password_creating(
            records_map_for_reuse_check=records_map,
            prompt_message=f"Оновлення пароля для логіна '{new_login}' на платформі '{new_platform_name}'",
            current_site_for_reuse=new_platform_name,
            current_login_for_reuse=new_login,
            allow_empty_for_no_change=True
        )

        final_password_to_save = original_password_value
        password_changed_flag = False
        if new_password_value is None:
            print("Зміна пароля скасована. Пароль не змінено.")
        elif new_password_value == "":
            print("Пароль не змінено (залишено поточний).")
        else:
            if original_password_value != new_password_value:
                password_changed_flag = True
            final_password_to_save = new_password_value
            if password_changed_flag:
                print("Пароль успішно оновлено.")
            else:
                print("Введено той самий пароль. Пароль не змінено.")

        updated_entry_data = {
            "login": new_login,
            "password": final_password_to_save,
            "data_created": record_to_edit_original_data.get("data_created"),
            "last_modified": datetime.now().isoformat()
        }

        records_map[original_platform_name].pop(account_idx_to_edit)
        if not records_map[original_platform_name]:
            del records_map[original_platform_name]

        records_map.setdefault(new_platform_name, []).append(updated_entry_data)

        log_details_parts = []
        if original_platform_name != new_platform_name:
            log_details_parts.append(f"платформу змінено з '{original_platform_name}' на '{new_platform_name}'")
        else:
            log_details_parts.append(f"платформа залишилася '{original_platform_name}'")
        if original_login_for_log != new_login:
            log_details_parts.append(f"логін змінено з '{original_login_for_log}' на '{new_login}'")
        else:
            log_details_parts.append(f"логін залишився '{new_login}'")
        if password_changed_flag:
            log_details_parts.append("пароль було змінено")
        else:
            log_details_parts.append("пароль не змінено")
        log_action_description = (f"Редаговано запис (початкова платформа: '{original_platform_name}', "
                                  f"початковий логін: '{original_login_for_log}'). "
                                  f"Зміни: {'; '.join(log_details_parts)}.")

        if self.save_data_to_file(current_file_data):
            print("Запис успішно оновлено та збережено у файл.")
            self.log_change(log_action_description)
        else:
            print("Помилка при збереженні оновленого запису у файл.")

    def select_account(self, current_file_data: dict):
        if not current_file_data or "records" not in current_file_data:
            print("Дані не завантажено або відсутні записи.")
            return None

        resources = current_file_data.get("records", {})
        if not resources:
            print("У вас немає жодного запису.")
            return None

        all_platforms = list(resources.keys())
        platform_dict_for_selection = {str(i + 1): platform for i, platform in enumerate(all_platforms)}

        print("\nОберіть платформу:")
        for num_idx, platform_name_iter in platform_dict_for_selection.items():
            print(f"{num_idx}: {platform_name_iter}")

        usr_platform_choice_num = input("Введіть номер платформи: ").strip()
        selected_platform_name = platform_dict_for_selection.get(usr_platform_choice_num)

        if not selected_platform_name:
            print("Неправильний вибір платформи!")
            return None

        platform_accounts = resources.get(selected_platform_name, [])
        if not platform_accounts:
            print(f"Для платформи '{selected_platform_name}' немає записів.")
            return None

        print(f"\nАкаунти для платформи '{selected_platform_name}':")
        for idx, account in enumerate(platform_accounts):
            print(f" {idx + 1}. Логін: {account.get('login')}, Пароль: {account.get('password')}")

        try:
            usr_account_choice_idx = int(input("Введіть номер акаунту: ")) - 1
            if not (0 <= usr_account_choice_idx < len(platform_accounts)):
                print("Неправильний номер акаунту!")
                return None
            return selected_platform_name, usr_account_choice_idx
        except ValueError:
            print("Будь ласка, введіть номер.")
            return None
        except Exception as e:
            print(f"Сталася помилка під час вибору акаунту: {e}")
            return None

    def display_records(self):
        current_file_data = self.load_data_from_file()
        if not current_file_data or "records" not in current_file_data:
            return

        resources = current_file_data["records"]
        if not resources:
            print("\n!!! Створених записів немає. !!!")
            return

        print("\n(1).Вивести все.\n"
              "(2).Вивести 1 запис.\n"
              "(3).Скасувати дію.")
        u_choice = str(input("Оберіть дію: "))

        if u_choice in ("1", "2"):
            all_platforms = list(resources.keys())
            platform_dict = {str(i + 1): platform for i, platform in enumerate(all_platforms)}

            if u_choice == "1":
                selected_platforms = all_platforms

            elif u_choice == "2":
                print("")
                for i, platform in enumerate(all_platforms):
                    print(f"{i + 1}: {platform}")

                usr_choice = input("Оберіть платформу: ").strip()
                platform = platform_dict.get(usr_choice)

                if not platform:
                    print("Неправильний вибір платформи!")
                    return

                selected_platforms = [platform]

            for platform in selected_platforms:
                print(f"\n +++ {platform} +++")
                for idx, account in enumerate(resources[platform]):
                    print(f" Account #{idx + 1}")
                    for key, value in account.items():
                        print(f"|===| {key}: {value}")

        elif u_choice == "3":
            return
        else:
            print("Неправильний вибір операції!")

    def delete_record(self):
        print("\n--- Видалення запису ---")
        current_file_data = self.load_data_from_file()
        if current_file_data is None:
            print("Не вдалося завантажити дані для видалення.")
            return

        if "records" not in current_file_data or not isinstance(current_file_data.get("records"), dict):
            print("Структура записів відсутня.")
            current_file_data["records"] = {}

        records_map = current_file_data["records"]
        selection_result = self.select_account(current_file_data)
        if not selection_result:
            return

        selected_platform, account_idx_to_delete = selection_result

        if selected_platform not in records_map or \
                not isinstance(records_map[selected_platform], list) or \
                not (0 <= account_idx_to_delete < len(records_map[selected_platform])):
            print("Помилка: не вдалося знайти обраний запис для видалення.")
            return

        record_details = records_map[selected_platform][account_idx_to_delete]

        confirm = input(
            f"Ви впевнені, що хочете видалити запис: Платформа='{selected_platform}', "
            f"Логін='{record_details.get('login')}'? (1 - так, 2 - ні): ").lower()

        if confirm == '1':
            try:
                deleted_entry_for_log = records_map[selected_platform].pop(account_idx_to_delete)

                if not records_map[selected_platform]:
                    del records_map[selected_platform]

                if self.save_data_to_file(current_file_data):
                    print("Запис успішно видалено з файлу.")
                    self.log_change(
                        f"Видалено запис для платформи '{selected_platform}', логін '{deleted_entry_for_log.get('login')}'.")
                else:
                    print("Помилка при збереженні змін після видалення запису.")
            except IndexError:
                print("Помилка: Некоректний індекс для видалення (можливо, дані змінилися).")
            except KeyError:
                print("Помилка: Не вдалося знайти платформу для видалення (можливо, дані змінилися).")
            except Exception as e:
                print(f"Невідома помилка під час видалення запису: {e}")
        else:
            print("Видалення скасовано.")
        return

    def create_backup(self, master_password: str) -> bool:
        print("\n--- Створення резервної копії ---")

        if os.path.exists(BACKUP_FILE_NAME):
            choice = input(f"Файл резервної копії '{BACKUP_FILE_NAME}' вже існує. "
                           f"Замінити його? (1).так (2).ні: ").lower()
            if choice != '1':
                print("Створення резервної копії скасовано.")
                return False

        current_plaintext_data = self.load_data_from_file()
        if current_plaintext_data is None:
            print("Помилка: не вдалося завантажити дані з основного файлу для резервного копіювання.")
            return False

        if self.security_system.write_encrypted_data_to_backup_file(master_password, current_plaintext_data,
                                                                    BACKUP_FILE_NAME):
            return True
        else:
            return False


class NotificationSystem:
    def __init__(self, password_analyzer: PasswordAnalysisSystem):
        self.password_analyzer = password_analyzer
        self.PASSWORD_AGE_THRESHOLD_DAYS = 30

    def check_password_ages(self, records_map: dict) -> list[str]:
        notifications = []
        now = datetime.now()
        for site_name, entries in records_map.items():
            for entry in entries:
                date_str = entry.get("last_modified") or entry.get("data_created")
                if date_str:
                    try:
                        password_date = datetime.fromisoformat(date_str)
                        age = now - password_date
                        if age.days > self.PASSWORD_AGE_THRESHOLD_DAYS:
                            notifications.append(
                                f"Пароль для '{site_name}' (логін: {entry.get('login')}) не змінювався більше "
                                f"{self.PASSWORD_AGE_THRESHOLD_DAYS} днів (остання зміна: "
                                f"{password_date.strftime('%Y-%m-%d')}). Рекомендовано оновити."
                            )
                    except ValueError:
                        notifications.append(
                            f"Некоректний формат дати для запису '{site_name}' (логін: {entry.get('login')})."
                        )
        return notifications

    def check_weak_passwords(self, records_map: dict) -> list[str]:
        notifications = []
        for site_name, entries in records_map.items():
            for entry in entries:
                password = entry.get("password")
                if password:
                    strength = self.password_analyzer.assess_strength(password)
                    if strength in ["Дуже слабкий", "Слабкий"]:
                        notifications.append(
                            f"Пароль для '{site_name}' (логін: {entry.get('login')}) є ненадійним (оцінка: {strength})."
                        )
        return notifications

    def check_for_reused_passwords_globally(self, records_map: dict) -> list[str]:
        notifications = []
        password_occurrences = {}
        for site_name, entries in records_map.items():
            for entry in entries:
                password = entry.get("password")
                login = entry.get("login")
                if password:
                    password_occurrences.setdefault(password, []).append(f"'{site_name}' (логін: {login})")

        for password, used_in in password_occurrences.items():
            if len(used_in) > 1:
                locations_str = ", ".join(used_in)
                notifications.append(
                    f"Пароль '{password[:3]}...{password[-3:]}' (частково) "
                    f"використовується повторно: {locations_str}."
                )
        return notifications

    def run_all_checks(self, records_map: dict | None) -> list[str]:
        if not records_map:
            return ["Немає записів для перевірки."]

        all_notifications = []
        print("Запуск перевірки безпеки паролів...")

        age_notifications = self.check_password_ages(records_map)
        if age_notifications:
            all_notifications.append("\n--- Сповіщення про вік паролів ---")
            all_notifications.extend(age_notifications)

        weak_notifications = self.check_weak_passwords(records_map)
        if weak_notifications:
            all_notifications.append("\n--- Сповіщення про ненадійні паролі ---")
            all_notifications.extend(weak_notifications)

        reused_notifications = self.check_for_reused_passwords_globally(records_map)
        if reused_notifications:
            all_notifications.append("\n--- Сповіщення про повторне використання паролів ---")
            all_notifications.extend(reused_notifications)

        if not all_notifications:
            return ["Усі перевірки пройдено, критичних сповіщень немає."]

        return all_notifications


class InterfaceSystem:
    def __init__(self, security_system: SecuritySystem):
        self.security_system = security_system
        self.record_manager = RecordManagementSystem(FILE_NAME, self.security_system)
        self.password_analyzer = self.record_manager.password_analyzer
        self.notification_system = NotificationSystem(self.password_analyzer)
        self.current_master_password = None

        self.operations = {"1": ["(1).Переглянути записи.", self.record_manager.display_records],
                           "2": ["(2).Створити запис.", self.record_manager.create_new_record],
                           "3": ["(3).Редагувати запис.", self.record_manager.edit_record],
                           "4": ["(4).Видалити запис.", self.record_manager.delete_record],
                           "5": ["(5).Створити резервну копію файлу.", self.manual_backup],
                           "6": ["(6).Вийти з програми.", self.quit_program]
                           }

    def manual_backup(self):
        self.record_manager.create_backup(self.current_master_password)

    def quit_program(self):
        if self.current_master_password:
            print("\nШифрування основного файлу перед виходом...")
            if self.security_system.encrypt_records_in_file_on_disk(self.current_master_password):
                perform_auto_backup_on_exit = True
                if os.path.exists(BACKUP_FILE_NAME):
                    choice = input(
                        f"Файл автоматичної резервної копії '{BACKUP_FILE_NAME}' вже існує. "
                        f"Замінити його поточною зашифрованою версією? (1).так (2).ні: "
                    ).lower()

                    if choice != '1':
                        print("Автоматичне резервне копіювання при виході скасовано користувачем.")
                        perform_auto_backup_on_exit = False

                if perform_auto_backup_on_exit:
                    try:
                        shutil.copy2(FILE_NAME, BACKUP_FILE_NAME)
                        print(f"Автоматичну резервну копію (зашифровану) збережено/оновлено у '{BACKUP_FILE_NAME}'.")
                    except Exception as e:
                        print(f"ПОМИЛКА створення автоматичної резервної копії: {e}")
            else:
                choice = input(
                    "ПОМИЛКА: Не вдалося зашифрувати основний файл! Резервну копію не створено. "
                    "Все одно вийти (файл залишиться розшифрованим)? (1).так (2).ні: "
                ).lower()
                if choice != '1':
                    return

        print("Закриття програми.. До по ба че н ня!")
        quit()

    def program_interface(self):
        print("+++ ВЕЛКОМ ТУ МАЙ МЕНЕДЖЕР ПАРОЛІВ +++\n")

        if check_file_exists():
            login_success = False
            for attempt in range(3):
                entered_password = str(input(f"Введіть майстер-пароль (спроба {attempt + 1}/3): "))
                if self.security_system.verify_password(entered_password):
                    if self.security_system.decrypt_records_in_file_on_disk(entered_password):
                        self.current_master_password = entered_password
                        print("\n##### ВІТАЮ В СИСТЕМІ! #####")
                        print("Записи було успішно розшифровано.")
                        login_success = True
                        break
                    else:
                        print(
                            "Пароль вірний, але не вдалося розшифрувати записи. :(")
                        self.current_master_password = None
                else:
                    print("Пароль не вірний! :(")

            if not login_success:
                print("Спроби входу вичерпано. Завершення роботи..")
                return
        else:
            print("Щоб розпочати, вам потрібно створити файл JSON та придумати майстер-пароль")
            if not file_operating():
                print("Помилка під час початкового налаштування. Завершення роботи..")
                return
            print(f"Файл '{FILE_NAME}' створено. Будь ласка, перезапустіть програму. :)")

            return

        print("\nЗавантаження даних для автоматичної перевірки безпеки...")
        current_file_content_on_login = self.record_manager.load_data_from_file()

        if current_file_content_on_login and "records" in current_file_content_on_login:
            records_map_on_login = current_file_content_on_login.get("records")
            initial_notifications = self.notification_system.run_all_checks(records_map_on_login)
            if initial_notifications and not (
                    len(initial_notifications) == 1 and "Усі перевірки пройдено" in initial_notifications[0]):
                print("\n--- АКТУАЛЬНІ СПОВІЩЕННЯ БЕЗПЕКИ ---")
                for notification_line in initial_notifications:
                    print(notification_line)
                print("------------------------------------")
            else:
                print("Автоматична перевірка безпеки: критичних сповіщень немає.")
        else:
            print("Не вдалося завантажити записи для автоматичної перевірки безпеки.")

        while True:
            print("\n=== Доступні дії ===")
            for operation_data in self.operations.values():
                print(operation_data[0])

            user_choice_key = str(input("Оберіть дію: "))

            if user_choice_key in self.operations.keys():
                self.operations[user_choice_key][1]()
            else:
                print("Невірний вибір. Спробуйте ще раз.")


def check_file_exists() -> bool:
    return os.path.exists(FILE_NAME)


def file_operating():
    input_choice = True
    master_password = None

    while input_choice:
        input_choice = input("Продовжити дію(1), Скасувати дію(2): ")
        if input_choice == "2":
            print("До по ба че н ня!")
            quit()

        print("Придумайте майстер-пароль, але не забувайте його, оскільки назавжди втратите доступ до записів!")
        master_password = input("Будь ласка, введіть пароль: ")
        if not master_password:
            print("Майстер-пароль не може бути порожнім.")
            continue

        confirm_password = input("Підтвердіть майстер-пароль: ")
        if master_password == confirm_password:
            break
        else:
            print("Паролі не співпадають. Спробуйте ще раз.")

    print(f"Майстер-пароль було успішно створено!")
    global sec_system
    return create_file(master_password, sec_system.encode_password(master_password))


def create_file(master_password_copy: str, hashed_password: str):
    global sec_system
    encryption_key = sec_system.get_encryption_key(master_password_copy)
    initial_records_structure_to_encrypt = {"records": {}}
    encrypted_content_blob = sec_system.encrypt_data(initial_records_structure_to_encrypt, encryption_key)

    data_to_store = {
        "hash_master_password": hashed_password,
        "encrypted_content": encrypted_content_blob
    }
    try:
        with open(FILE_NAME, 'w') as records_file:
            json.dump(data_to_store, records_file, indent=4)
        print(f"Файл було успішно створено!")
        print(f"Майстер-пароль збережено у '{FILE_NAME}'.")
        return True
    except exception as e:
        print(f"Помилка: щось пішло не так при створенні файла:'{e}'.")
        return False


sec_system = SecuritySystem()
Ps_Manager = InterfaceSystem(sec_system)
Ps_Manager.program_interface()
