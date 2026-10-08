# 🛡️ SRM-Auditor CLI (Shared Responsibility Model)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![boto3](https://img.shields.io/badge/boto3-AWS-orange?logo=amazonaws)
![moto](https://img.shields.io/badge/moto-Mocking-lightgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-brightgreen)

**SRM-Auditor** to narzędzie CLI (Command Line Interface) napisane w Pythonie, które weryfikuje przestrzeganie **Shared Responsibility Model** na koncie AWS. Skupia się wyłącznie na warstwie odpowiedzialności klienta, czyli bezpieczeństwie **"IN the cloud"** (konfiguracja usług, ochrona danych, warstwa sieciowa).

Zamiast teoretyzować o granicach odpowiedzialności, to narzędzie w praktyce audytuje zaniedbania konfiguracyjne, które po stronie klienta mogą prowadzić do wycieków danych (np. brak S3 Block Public Access) lub kompromitacji środowiska (np. otwarty port SSH na świat).

## ✨ Główne funkcjonalności

- **Skanowanie zasobów (S3, EC2):** Weryfikuje kluczowe punkty styku na linii AWS-Klient.
- **Gotowość na CI/CD (Pipeline Breaker):** Zwraca odpowiednie kody wyjścia (Exit Codes: `0` dla sukcesu, `1` w przypadku znalezienia podatności), co pozwala zablokować wdrożenie w potokach DevSecOps.
- **Raportowanie JSON:** Generuje ustrukturyzowany, łatwy do parsowania (np. przez `jq`) plik wyników za pomocą natywnej biblioteki `json` i `pathlib`.
- **Wbudowane środowisko testowe (Mocking):** Obsługuje flagę `--mock`, która wykorzystuje bibliotekę `moto` do wygenerowania wirtualnej, izolowanej infrastruktury w pamięci RAM. Pozwala to na bezpieczne testy bez ryzyka kosztów czy naruszania prawdziwego środowiska AWS.

## 🚀 Instalacja

1. Sklonuj repozytorium i przejdź do folderu z projektem.
2. (Opcjonalnie) Utwórz środowisko wirtualne: `python -m venv venv && source venv/bin/activate`
3. Zainstaluj wymagane pakiety:
```bash
pip install boto3 moto