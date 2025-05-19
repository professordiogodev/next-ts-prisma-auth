🏗️ **Full Lab: Next.js 15 + Prisma + MySQL CRUD with E-mail/Password Auth**

---

## 📜 Table of Contents

| Phase | What you’ll build                           | Main folders affected                                                                                                                                               |
| ----- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** | Simple CRUD for **Product** entity          | `prisma/`, `src/app/(protected)/products/**`, `src/lib/prisma.ts`                                                                                                   |
| **B** | **E-mail & password** sign-up + login (JWT) | update `prisma/schema.prisma`, `src/app/(auth)/**`, `src/app/api/auth/[...nextauth]/route.ts`, `src/lib/auth.ts`, `src/lib/hash.ts`, `middleware.ts`, shared header |
| **C** | Redirect & Deploy on AWS                    | GitHub repo, remote-server folders                                                                                                                                  |

---

[**PHASE A – Run the CRUD project**](https://www.notion.so/FASE-A-Executar-o-projecto-CRUD-1f8c08bca56a80cb853cf103aa5f38e1?pvs=21)

[**PHASE B – Add JWT Auth (NextAuth v4)**](https://www.notion.so/FASE-B-Adicionar-JWT-Auth-NextAuth-v4-1f8c08bca56a80c6b832df76a7eb5e07?pvs=21)

[**PHASE C – Deploy on AWS EC2 (Ubuntu 22.04 LTS)**](https://www.notion.so/Fase-C-Deploy-na-AWS-EC2-Ubuntu-22-04-LTS-1f8c08bca56a8039ac9ae36ca09ff437?pvs=21)

---

# PHASE A – Run the CRUD project

*(Almost a literal transcript of your checklist; just minor language tweaks.)*

### 1. Prerequisites

| Tool                   | Version                                   |
| ---------------------- | ----------------------------------------- |
| **Node**               | ≥ 18                                      |
| **MySQL**              | 8.x (local, Docker or cloud)              |
| **Package manager**    | pnpm / npm / yarn (examples use **pnpm**) |
| **VS Code** (optional) | Prisma & ESLint extensions                |
| Terminal               | bash (macOS/Linux) or WSL/PowerShell      |

---

### 2. Create the project skeleton

```bash
pnpm create next-app@latest next15-prisma-mysql \
  --ts --app --eslint --tailwind --src-dir --import-alias "@/*" \
  --use-pnpm
```

* `--app` turns on the App Router (Next 14+) fully supported in Next 15.

---

### 3. Add Prisma + the MySQL driver

```bash
pnpm add prisma @prisma/client mysql2
pnpm dlx prisma init --datasource-provider mysql
```

Files created:

```
prisma/schema.prisma
.env
```

---

### 4. Create the MySQL database

```bash
mysql -u root -p -e "CREATE DATABASE next15_prisma;"
```

---

### 5. Configure the connection string

```ini
# .env
DATABASE_URL="mysql://root:password@localhost:3306/next15_prisma"
```

---

### 6. Model the **Product** entity

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

model Product {
  id          Int      @id @default(autoincrement())
  name        String   @db.VarChar(100)
  description String?  @db.Text
  price       Decimal  @db.Decimal(10,2)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}
```

---

### 7. Push the schema & generate the client

```bash
pnpm prisma db push
pnpm prisma generate
```

---

### 8. (Optional) Seed sample data

`prisma/seed.ts`

```ts
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
  await prisma.product.createMany({
    data: [
      { name: 'Tea',  description: 'Green tea', price: 4.90 },
      { name: 'Cake', description: 'Chocolate', price: 12.50 },
    ],
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
```

```bash
pnpm dlx tsx prisma/seed.ts
```

---

### 9. Prisma helper (singleton)

This helper with `global.prisma` is **best practice for Next.js + Prisma in development**, preventing the creation of **multiple PrismaClient instances** during hot reload.

`src/lib/prisma.ts`

```ts
import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

export const prisma =
  global.prisma ??
  new PrismaClient({ log: ['query'] });

if (process.env.NODE_ENV !== 'production') global.prisma = prisma;
```

---

### 10. Server Actions for CRUD

`src/app/(protected)/products/actions.ts`

```ts
'use server';

import { prisma } from '@/lib/prisma';
import { revalidatePath } from 'next/cache';

// CREATE
export async function createProduct(data: FormData) {
  await prisma.product.create({
    data: {
      name:        data.get('name') as string,
      description: data.get('description') as string,
      price:       Number(data.get('price')),
    }
  });
  revalidatePath('/products');
}

// UPDATE
export async function updateProduct(id: number, data: FormData) {
  await prisma.product.update({
    where: { id },
    data: {
      name:        data.get('name') as string,
      description: data.get('description') as string,
      price:       Number(data.get('price')),
    }
  });
  revalidatePath('/products');
}

// DELETE
export async function deleteProduct(id: number) {
  await prisma.product.delete({ where: { id } });
  revalidatePath('/products');
}
```

---

### 11. List products (READ)

`src/app/(protected)/products/page.tsx`

```tsx
import { prisma } from '@/lib/prisma';
import Link from 'next/link';

export default async function ProductsPage() {
  const products = await prisma.product.findMany({ orderBy: { id: 'desc' } });

  return (
    <main className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4">Products</h1>

      <Link href="/products/new" className="underline mb-4 inline-block">
        + New product
      </Link>

      <ul className="space-y-4">
        {products.map(p => (
          <li key={p.id} className="border p-4 rounded">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="font-medium">{p.name}</h2>
                <p className="text-sm text-gray-600">{p.description}</p>
              </div>
              <div className="text-right">
                <p className="font-mono">€ {p.price.toFixed(2)}</p>
                <Link
                  href={`/products/${p.id}`}
                  className="text-blue-500 underline ml-2"
                >
                  Edit
                </Link>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </main>
  );
}
```

---

### 12. Product Form (Client)

`src/components/ProductForm.tsx`

```tsx
'use client';

import { createProduct, updateProduct } from '@/app/(protected)/products/actions';
import { useRouter } from 'next/navigation';

export default function ProductForm({
  product,
}: {
  product?: { id: number; name: string; description: string | null; price: any };
}) {
  const router = useRouter();

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    product ? await updateProduct(product.id, fd) : await createProduct(fd);
    router.push('/products');
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <input
        name="name"
        placeholder="Name"
        defaultValue={product?.name ?? ''}
        required
        className="border p-2 w-full"
      />
      <textarea
        name="description"
        placeholder="Description"
        defaultValue={product?.description ?? ''}
        className="border p-2 w-full"
      />
      <input
        name="price"
        type="number"
        step="0.01"
        placeholder="Price"
        defaultValue={product?.price ?? ''}
        required
        className="border p-2 w-full"
      />
      <button className="bg-blue-600 text-white px-4 py-2">
        {product ? 'Update' : 'Create'}
      </button>
    </form>
  );
}
```

---

### 13. **Create** & **Edit** routes

*New Product page* — `src/app/(protected)/products/new/page.tsx`

```tsx
import ProductForm from '@/components/ProductForm';

export default function NewProduct() {
  return (
    <main className="max-w-md mx-auto p-6">
      <h1 className="text-xl font-semibold mb-4">Add product</h1>
      <ProductForm />
    </main>
  );
}
```

*Edit Product page* — `src/app/(protected)/products/[id]/page.tsx`

```tsx
import { prisma } from '@/lib/prisma';
import ProductForm from '@/components/ProductForm';
import { notFound } from 'next/navigation';

export default async function EditProduct({ params: { id } }: { params: { id: string } }) {
  const product = await prisma.product.findUnique({ where: { id: Number(id) } });
  if (!product) notFound();

  return (
    <main className="max-w-md mx-auto p-6">
      <h1 className="text-xl font-semibold mb-4">Edit product</h1>
      <ProductForm product={product} />
    </main>
  );
}
```

*(Optionally add a Delete button that calls `deleteProduct(id)`, too.)*

---

### 14. Run the app

```bash
pnpm dev
open http://localhost:3000/products
```

---

### 15. Quick DB inspection

```bash
pnpm prisma studio
```

---

# PHASE B – Add JWT Auth (NextAuth v4)

### Folder map

```
src
├─ app
│  ├─ (auth)/              # public pages
│  │   ├─ login/
│  │   └─ signup/
│  ├─ (protected)/         # requires session (your CRUD)
│  │   └─ products/…
│  └─ api/
│      └─ auth/[...nextauth]/route.ts
├─ components/
│  ├─ Header.tsx
│  └─ SignOutButton.tsx
└─ lib/
   ├─ prisma.ts
   ├─ hash.ts
   └─ auth.ts
middleware.ts
```

---

### 1. Install (once)

```bash
pnpm add next-auth @auth/prisma-adapter bcryptjs
```

---

### 2. Extend **`prisma/schema.prisma`**

```prisma
/////////////////////////////
// GENERATOR + DATASOURCE  //
/////////////////////////////

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

/////////////////////////////
//         MODELS          //
/////////////////////////////

model User {
  id            Int       @id @default(autoincrement())
  name          String?   @db.VarChar(50)
  email         String    @unique @db.VarChar(100)
  emailVerified DateTime?
  image         String?
  passwordHash  String    @db.VarChar(255)

  accounts      Account[]
  sessions      Session[]
  products      Product[]
}

model Account {
  id                 Int      @id @default(autoincrement())
  userId             Int
  type               String
  provider           String
  providerAccountId  String
  refresh_token      String?  @db.Text
  access_token       String?  @db.Text
  expires_at         Int?
  token_type         String?
  scope              String?
  id_token           String?  @db.Text
  session_state      String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
  @@unique([provider, providerAccountId])
}

model Session {
  id           Int      @id @default(autoincrement())
  sessionToken String   @unique
  userId       Int
  expires      DateTime

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
}

model VerificationToken {
  identifier String
  token      String   @unique
  expires    DateTime

  @@unique([identifier, token])
}

model Product {
  id          Int       @id @default(autoincrement())
  name        String    @db.VarChar(100)
  description String?   @db.Text
  price       Decimal   @db.Decimal(10, 2)
  createdAt   DateTime  @default(now())
  updatedAt   DateTime  @updatedAt

  userId Int?
  user   User? @relation(fields: [userId], references: [id])
}
```

```bash
pnpm prisma format
pnpm prisma migrate dev --name add_auth
pnpm prisma generate
```

---

### 3. Hash helpers

`src/lib/hash.ts`

```ts
import bcrypt from 'bcryptjs';
const ROUNDS = 10;
export const hashPassword   = (pw: string) => bcrypt.hash(pw, ROUNDS);
export const verifyPassword = (pw: string, hash: string) => bcrypt.compare(pw, hash);
```

---

### 4. NextAuth options

`src/lib/auth.ts`

```ts
import { PrismaAdapter } from '@auth/prisma-adapter';
import { prisma } from '@/lib/prisma';
import Credentials from 'next-auth/providers/credentials';
import { verifyPassword } from '@/lib/hash';
import { type NextAuthOptions } from 'next-auth';

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  session: { strategy: 'jwt' },
  secret:  process.env.NEXTAUTH_SECRET,
  pages:   { signIn: '/login' },

  providers: [
    Credentials({
      name: 'E-mail & Password',
      credentials: {
        email:    { label: 'E-mail', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(creds) {
        if (!creds?.email || !creds.password) return null;
        const user = await prisma.user.findUnique({ where: { email: creds.email } });
        if (!user) return null;
        return (await verifyPassword(creds.password, user.passwordHash))
          ? { id: String(user.id), email: user.email, name: user.name ?? null }
          : null;
      },
    }),
  ],
};
```

---

### 5. API route handler

`src/app/api/auth/[...nextauth]/route.ts`

```ts
import NextAuth from 'next-auth';
import { authOptions } from '@/lib/auth';

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
```

---

### 6. Sign-up flow

#### Server Action (Sign-up)

`src/app/(auth)/signup/actions.ts`

```ts
'use server';
import { prisma } from '@/lib/prisma';
import { hashPassword } from '@/lib/hash';
import { redirect } from 'next/navigation';

export async function signupAction(fd: FormData) {
  const email = fd.get('email') as string;
  const pw    = fd.get('password') as string;
  const name  = fd.get('name') as string | null;

  if (await prisma.user.findUnique({ where: { email } }))
    throw new Error('E-mail already registered');

  await prisma.user.create({
    data: { email, name, passwordHash: await hashPassword(pw) },
  });

  redirect('/login?signup=ok');
}
```

#### Sign-up page

`src/app/(auth)/signup/page.tsx`

```tsx
import { signupAction } from './actions';

export default function SignUp() {
  return (
    <main className="max-w-sm mx-auto p-8 space-y-4">
      <h1 className="text-2xl font-semibold">Create account</h1>

      <form action={signupAction} className="space-y-3">
        <input name="name"     placeholder="Name"      className="border p-2 w-full"/>
        <input name="email"    type="email"    placeholder="E-mail"   required className="border p-2 w-full"/>
        <input name="password" type="password" placeholder="Password" required className="border p-2 w-full"/>
        <button className="bg-blue-600 text-white px-4 py-2 w-full">Sign up</button>
      </form>

      <p className="text-sm">
        Already have an account? <a href="/login" className="underline">Log in</a>
      </p>
    </main>
  );
}
```

---

### 7. Login flow

`src/app/(auth)/login/page.tsx`

```tsx
'use client';
import { signIn } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';
import { useState } from 'react';

export default function Login() {
  const [error, setError] = useState('');
  const params = useSearchParams();

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const email = fd.get('email') as string;
    const password = fd.get('password') as string;

    const res = await signIn('credentials', { email, password, redirect: false });
    if (res?.error) setError('Invalid credentials');
    else window.location.href = '/products';
  }

  return (
    <main className="max-w-sm mx-auto p-8 space-y-4">
      <h1 className="text-2xl font-semibold">Log in</h1>

      {params.get('signup') === 'ok' && (
        <p className="p-2 bg-green-100 border">Account created – please log in.</p>
      )}
      {error && <p className="p-2 bg-red-100 border">{error}</p>}

      <form onSubmit={onSubmit} className="space-y-3">
        <input name="email"    type="email"    placeholder="E-mail"   required className="border p-2 w-full"/>
        <input name="password" type="password" placeholder="Password" required className="border p-2 w-full"/>
        <button className="bg-blue-600 text-white px-4 py-2 w-full">Log in</button>
      </form>

      <p className="text-sm">
        No account? <a href="/signup" className="underline">Sign up</a>
      </p>
    </main>
  );
}
```

---

### 8. Shared header + sign-out

`src/components/SignOutButton.tsx`

```tsx
'use client';
import { signOut } from 'next-auth/react';

export function SignOutButton({ email }: { email: string }) {
  return (
    <button onClick={() => signOut({ callbackUrl: '/login' })}>
      Sign out ({email})
    </button>
  );
}
```

`src/components/Header.tsx`

```tsx
import Link from 'next/link';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { SignOutButton } from './SignOutButton';

export default async function Header() {
  const session = await getServerSession(authOptions);

  return (
    <header className="p-4 border-b flex gap-6">
      <Link href="/">Home</Link>

      {session ? (
        <>
          <Link href="/products">Products</Link>
          <SignOutButton email={session.user?.email ?? ''} />
        </>
      ) : (
        <>
          <Link href="/login">Log in</Link>
          <Link href="/signup">Sign up</Link>
        </>
      )}
    </header>
  );
}
```

*(Import this header in `src/app/layout.tsx` or your global layout.)*

---

### 9. Protect CRUD routes

`src/app/(protected)/products/layout.tsx`

```tsx
import { getServerSession } from 'next-auth';
import { redirect } from 'next/navigation';
import { authOptions } from '@/lib/auth';

export default async function ProductsLayout({ children }: { children: React.ReactNode }) {
  const session = await getServerSession(authOptions);
  if (!session) redirect('/login');
  return children;
}
```

---

### 10. (Optional) Global gate via middleware

`middleware.ts`

```ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';

export const config = {
  matcher: ['/products/:path*'],
};

export async function middleware(req: NextRequest) {
  const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
  if (!token) {
    const login = new URL('/login', req.url);
    login.searchParams.set('from', req.nextUrl.pathname);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}
```

---

### 11. Environment variables

```dotenv
NEXTAUTH_SECRET=generate_a_long_random_string
NEXTAUTH_URL=http://localhost:3000
DATABASE_URL=mysql://root:password@localhost:3306/next15_prisma
```

*(Use the same values on Vercel, Render, etc.)*

---

## 12. Redirect Home (`/`) to Login

Instead of a static home page we create a route that **immediately redirects to `/login`**.
That way when someone hits the domain/IP they see the auth screen right away.

`src/app/page.tsx`

```tsx
import { redirect } from 'next/navigation';

export default function Home() {
  redirect('/login');          // always redirect
}
```

*(If you prefer to send an authenticated user to `/products`, move this logic to `middleware.ts` and test the token before redirecting.)*

---

### 🧪 Quick test

1. `pnpm dev`
2. Visit `/signup` → create account → redirected to `/login`
3. Login → land on `/products` (CRUD list)
4. Header now shows **Products / Sign out**; non-auth links disappear
5. **Sign out** ends the session and redirects to `/login`
6. Direct access to `/products` while logged out → redirected

---

# PHASE C – Deploy on AWS EC2 (Ubuntu 22.04 LTS)

> **Prerequisites**
> • SSH key **diogo-chave.pem** (provided by the instructor or generated by you)
> • AWS account with permission to create instances & security groups
> • Git repo containing the final lab code

### 1. Launch the instance

1. AWS Console → **EC2 → Launch Instance**

   * **AMI**: *Ubuntu Server 22.04 LTS (64-bit x86)*
   * **Type**: t3.micro (for testing)
   * **Key pair**: **diogo-chave.pem**
   * **Security group**:

     * **TCP 80** (HTTP) – 0.0.0.0/0
     * **TCP 443** (HTTPS) – 0.0.0.0/0 (if you’ll use Nginx/SSL)
     * **TCP 3000** (Next.js dev/prod direct) – 0.0.0.0/0
     * **TCP 22** (SSH) – your IP
2. Launch and note the **Public IPv4 Address** (e.g. `3.115.24.17`).

### 2. Connect via SSH

```bash
chmod 400 diogo-chave.pem                         # ensure correct perms
ssh -i diogo-chave.pem ubuntu@3.115.24.17
```

### 3. Install basic dependencies

```bash
# Node 18 LTS + pnpm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs build-essential git
sudo npm install -g pnpm

# (Optional) Local MySQL – quick tests
sudo apt-get update && sudo apt-get install -y mysql-server
sudo mysql -e "CREATE DATABASE next15_prisma;"
```

*Production alternative: use managed RDS MySQL and point `DATABASE_URL` there.*

### 4. Clone the project & set env vars

```bash
git clone https://github.com/<your-repo>/next15-prisma-mysql.git
cd next15-prisma-mysql
cp .env.example .env             # or create it manually

# .env (sample values)
DATABASE_URL="mysql://root:password@localhost:3306/next15_prisma"
NEXTAUTH_SECRET=$(openssl rand -hex 32)
NEXTAUTH_URL="http://3.115.24.17"
```

### 5. Build & migrate

```bash
pnpm install
pnpm prisma migrate deploy       # apply migrations in production
pnpm prisma generate
pnpm build                       # build Next.js
```

### 6. Start in production mode

For quick tests:

```bash
pnpm start                       # runs on :3000
```

In production, use a process manager (e.g. **pm2**):

```bash
sudo npm install -g pm2
pm2 start "pnpm start" --name next15
pm2 save
```

### 7. (Optional) Nginx reverse proxy

```bash
sudo apt-get install -y nginx
sudo rm /etc/nginx/sites-enabled/default
sudo tee /etc/nginx/sites-available/next <<'EOF'
server {
    listen 80;
    server_name 3.115.24.17;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
sudo ln -s /etc/nginx/sites-available/next /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

*(Add Certbot + Let’s Encrypt for HTTPS.)*

### 8. Test

1. Open `http://3.115.24.17/` → should redirect to **/login**.
2. Create an account, log in, confirm **/products** works.
3. Log out and verify that hitting `/products` redirects to `/login`.

> **Quick troubleshooting tips**
> • `pm2 logs next15` or `journalctl -u nginx` for errors
> • `sudo ufw status` to confirm open ports
> • `pnpm prisma studio --browser` via SSH to inspect the DB

---

## ✅ Added section

* **Home-to-Login redirect** (`src/app/page.tsx`)
* **Complete EC2 deployment guide** using **diogo-chave.pem**: open ports, install deps, migrate, run the app, and test via public IP.

Ready to put students hands-on in a real environment! 🚀
