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
          <Link href="/products">Produtos</Link>
          <SignOutButton email={session.user?.email ?? ''} />
        </>
      ) : (
        <>
          <Link href="/login">Login</Link>
          <Link href="/signup">Registar</Link>
        </>
      )}
    </header>
  );
}
