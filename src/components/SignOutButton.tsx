'use client';
import { signOut } from 'next-auth/react';

export function SignOutButton({ email }: { email: string }) {
  return (
    <button onClick={() => signOut({ callbackUrl: '/login' })}>
      Sair ({email})
    </button>
  );
}
