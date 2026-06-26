# Ahmad Massd — Security Blog

Personal cybersecurity blog built with [Hugo](https://gohugo.io/) and the [Blowfish](https://blowfish.page) theme.

## Local Development

**Prerequisites:** Hugo Extended v0.112+, Git

```bash
# Clone with submodules (includes Blowfish theme)
git clone --recurse-submodules https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

# Serve locally with drafts
hugo server -D
```

Site available at `http://localhost:1313`

---

## Cloudflare Pages Deployment

### 1. Push to GitHub

```bash
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### 2. Connect to Cloudflare Pages

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **Create application** → **Pages**
2. Connect your GitHub repository
3. Set build settings:

| Setting | Value |
|---------|-------|
| Framework preset | Hugo |
| Build command | `hugo --minify` |
| Build output directory | `public` |

4. Add environment variable:

| Variable | Value |
|----------|-------|
| `HUGO_VERSION` | `0.163.3` |

5. Click **Save and Deploy**

### 3. Update baseURL

After deployment, update `config/_default/hugo.toml`:

```toml
baseURL = "https://your-actual-domain.pages.dev/"
```

---

## Adding Content

```bash
# New blog post
hugo new content posts/my-post-title/index.md

# Build for production
hugo --minify
```

## Project Structure

```
blog/
├── config/_default/       # Site configuration
│   ├── hugo.toml
│   ├── languages.en.toml
│   └── menus.en.toml
├── content/
│   ├── posts/             # Blog posts (page bundles)
│   └── about/             # About page
├── assets/img/            # Author photo, static images
├── themes/blowfish/       # Theme (git submodule)
└── .gitignore
```
