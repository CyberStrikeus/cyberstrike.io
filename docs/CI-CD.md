# Cyberstrike CI/CD Kullanım Rehberi

Bu doküman, Cyberstrike projesinin CI/CD pipeline'ını ve release süreçlerini açıklar.

---

## Genel Bakış

Cyberstrike, **trunk-based development** stratejisi kullanır:

- Tek ana branch: `main`
- Release'ler tag-based: `v1.0.7`, `v1.0.8-beta.1`
- PR'lar otomatik kontrol edilir
- Production deploy ayrı branch üzerinden

### Workflow'lar

| Workflow | Dosya | Trigger | Açıklama |
|----------|-------|---------|----------|
| PR Check: TypeScript Validation | `typecheck.yml` | PR açılınca | TypeScript tip kontrolü |
| PR Check: Run Tests | `test.yml` | PR açılınca | Linux + Windows testleri |
| Release: CLI to npm + Desktop to GitHub | `release-cli.yml` | `v*` tag | npm ve GitHub release |
| Deploy: SST to Cloudflare | `deploy.yml` | `production` push | Backend deploy |

---

## 1. Günlük Geliştirme

Normal geliştirme `main` branch üzerinde yapılır. Push'lar hiçbir workflow tetiklemez.

```bash
# Kod yaz
git add .
git commit -m "feat: yeni özellik ekle"
git push origin main
```

### Commit Mesaj Formatı (Conventional Commits)

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Type'lar:**
- `feat`: Yeni özellik
- `fix`: Bug düzeltme
- `docs`: Dokümantasyon
- `style`: Kod formatı (fonksiyonellik değişmez)
- `refactor`: Kod refactor
- `test`: Test ekleme/düzeltme
- `chore`: Build, CI, dependency güncelleme

**Örnekler:**
```bash
git commit -m "feat(browser): add interactive Playwright installation"
git commit -m "fix(auth): resolve token refresh issue"
git commit -m "docs: update CI/CD documentation"
git commit -m "chore: bump version to 1.0.7"
```

---

## 2. Pull Request Süreci

Feature branch'ler üzerinden PR açıldığında otomatik kontroller çalışır.

### Adımlar

```bash
# 1. Feature branch oluştur
git checkout -b feature/yeni-ozellik

# 2. Geliştirme yap
# ... kod yaz ...

# 3. Commit ve push
git add .
git commit -m "feat: yeni özellik açıklaması"
git push origin feature/yeni-ozellik

# 4. GitHub'da PR aç
gh pr create --title "feat: yeni özellik" --body "Açıklama..."
```

### Otomatik Kontroller

PR açıldığında şu workflow'lar çalışır:

| Workflow | Kontrol | Süre |
|----------|---------|------|
| PR Check: TypeScript Validation | Tip hataları | ~1 dk |
| PR Check: Run Tests (Linux + Windows) | E2E testler | ~5 dk |

PR'da ✅ veya ❌ işareti görünür. Tüm kontroller geçmeden merge yapılmamalıdır.

### PR Merge

```bash
# Squash merge (önerilen)
gh pr merge --squash

# Veya GitHub UI'dan "Squash and merge"
```

---

## 3. Release Süreci

### 3.1 Stable Release (Örn: v1.0.7)

Production-ready sürümler için kullanılır.

```bash
# 1. Versiyon güncelle (package.json)
# packages/cyberstrike/package.json içinde version alanını güncelle

# 2. Commit et
git add .
git commit -m "chore: bump version to 1.0.7"
git push origin main

# 3. Tag oluştur
git tag v1.0.7

# 4. Tag'i push et (workflow tetiklenir)
git push origin v1.0.7
```

**Sonuç:**
- ✅ npm'e `@cyberstrike-io/cli@1.0.7` yayınlanır (`latest` tag)
- ✅ GitHub Release oluşur
- ✅ Desktop binary'ler (Windows, macOS, Linux) eklenir

**Kullanıcı kurulumu:**
```bash
npm install -g @cyberstrike-io/cli
# veya
npm install -g @cyberstrike-io/cli@1.0.7
```

### 3.2 Beta Release (Örn: v1.0.8-beta.1)

Test amaçlı erken sürümler için kullanılır.

```bash
git tag v1.0.8-beta.1
git push origin v1.0.8-beta.1
```

**Sonuç:**
- ✅ npm'e `@cyberstrike-io/cli@1.0.8-beta.1` yayınlanır (`beta` tag)
- ✅ GitHub Pre-release oluşur

**Kullanıcı kurulumu:**
```bash
npm install -g @cyberstrike-io/cli@beta
```

### 3.3 Diğer Pre-release Türleri

| Tür | Tag Formatı | npm Tag | Kullanım |
|-----|-------------|---------|----------|
| Alpha | `v1.0.8-alpha.1` | `alpha` | Erken geliştirme, unstable |
| Beta | `v1.0.8-beta.1` | `beta` | Feature-complete, test aşaması |
| RC | `v1.0.8-rc.1` | `rc` | Release candidate, son testler |
| Stable | `v1.0.8` | `latest` | Production-ready |

```bash
# Alpha release
git tag v1.0.8-alpha.1 && git push origin v1.0.8-alpha.1

# Beta release
git tag v1.0.8-beta.1 && git push origin v1.0.8-beta.1

# Release candidate
git tag v1.0.8-rc.1 && git push origin v1.0.8-rc.1

# Stable release
git tag v1.0.8 && git push origin v1.0.8
```

---

## 4. Production Deploy

Backend/API değişikliklerini production'a almak için kullanılır.

```bash
# main'den production'a push
git push origin main:production
```

**Workflow:** `Deploy: SST to Cloudflare (Production)`

**Ne deploy edilir:**
- SST (Serverless Stack) ile Cloudflare Workers
- API endpoints
- Database migrations (varsa)

---

## 5. Manuel Workflow Tetikleme

Herhangi bir workflow'u manuel olarak çalıştırabilirsin:

### GitHub UI
1. GitHub repo → Actions tab
2. Sol menüden workflow seç
3. "Run workflow" butonuna tıkla
4. Branch seç ve "Run workflow"

### GitHub CLI
```bash
# Release workflow'u manuel tetikle
gh workflow run "Release: CLI to npm + Desktop to GitHub"

# Test workflow'u manuel tetikle
gh workflow run "PR Check: Run Tests (Linux + Windows)"
```

---

## 6. Hata Durumları

### Yanlış Tag Attım

```bash
# Local tag'i sil
git tag -d v1.0.7

# Remote tag'i sil
git push origin :v1.0.7

# veya
git push origin --delete v1.0.7
```

### Workflow Başarısız Oldu

1. GitHub Actions → İlgili workflow run'a tıkla
2. Hata loglarını incele
3. Sorunu düzelt ve tekrar dene

```bash
# Aynı tag ile tekrar release (önce sil, sonra tekrar at)
git push origin :v1.0.7
git tag -d v1.0.7
git tag v1.0.7
git push origin v1.0.7
```

### npm Publish Başarısız

- `NPM_TOKEN` secret'ının geçerli olduğundan emin ol
- npm'de paket adının kullanılabilir olduğunu kontrol et
- 2FA gerektiren hesaplarda automation token kullan

---

## 7. Versiyon Yönetimi

### Semantic Versioning (SemVer)

Format: `MAJOR.MINOR.PATCH`

| Değişiklik | Ne Zaman | Örnek |
|------------|----------|-------|
| MAJOR | Breaking change | `1.0.0` → `2.0.0` |
| MINOR | Yeni özellik (backward compatible) | `1.0.0` → `1.1.0` |
| PATCH | Bug fix | `1.0.0` → `1.0.1` |

### Versiyon Güncelleme

```bash
# Manuel güncelleme
# packages/cyberstrike/package.json dosyasını düzenle

# Commit
git add packages/cyberstrike/package.json
git commit -m "chore: bump version to 1.0.8"
git push origin main

# Tag ve release
git tag v1.0.8
git push origin v1.0.8
```

---

## 8. Best Practices

### Do's ✅

- Her release öncesi testlerin geçtiğinden emin ol
- Semantic versioning kurallarına uy
- Anlamlı commit mesajları yaz
- Breaking change'lerde MAJOR versiyon artır
- Beta sürümleri production'a almadan önce test et

### Don'ts ❌

- Direkt `main`'e force push yapma
- Test etmeden release yapma
- Aynı versiyon numarasını tekrar kullanma
- npm token'ı kod içinde bırakma

---

## 9. Örnek Senaryolar

### Senaryo 1: Bug Fix Release

```bash
# 1. Bug'ı düzelt
git add .
git commit -m "fix(auth): resolve login timeout issue"
git push origin main

# 2. Patch version artır
# package.json: "version": "1.0.6" → "1.0.7"
git add .
git commit -m "chore: bump version to 1.0.7"
git push origin main

# 3. Release
git tag v1.0.7
git push origin v1.0.7
```

### Senaryo 2: Yeni Özellik + Beta Test

```bash
# 1. Özellik geliştir
git add .
git commit -m "feat(browser): add screenshot capture"
git push origin main

# 2. Beta release
git tag v1.1.0-beta.1
git push origin v1.1.0-beta.1

# 3. Feedback al, düzelt
git add .
git commit -m "fix(browser): improve screenshot quality"
git push origin main

# 4. İkinci beta
git tag v1.1.0-beta.2
git push origin v1.1.0-beta.2

# 5. Stable release
# package.json: "version": "1.1.0"
git add .
git commit -m "chore: bump version to 1.1.0"
git push origin main
git tag v1.1.0
git push origin v1.1.0
```

### Senaryo 3: Hotfix

```bash
# Kritik bug için hızlı fix
git add .
git commit -m "fix(critical): patch security vulnerability"
git push origin main

# Hemen release
# package.json: "version": "1.0.8"
git add .
git commit -m "chore: bump version to 1.0.8"
git push origin main
git tag v1.0.8
git push origin v1.0.8
```

---

## 10. Useful Commands

```bash
# Tüm tag'leri listele
git tag -l

# Son 5 tag
git tag -l | tail -5

# Tag detayı
git show v1.0.7

# Workflow durumu
gh run list --limit 5

# Workflow logları
gh run view <run-id> --log

# npm'deki versiyonlar
npm view @cyberstrike-io/cli versions

# npm'deki latest version
npm view @cyberstrike-io/cli version

# npm'deki beta version
npm view @cyberstrike-io/cli dist-tags.beta
```

---

## Kaynaklar

- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [npm Publishing](https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry)
