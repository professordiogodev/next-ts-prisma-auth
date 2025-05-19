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
    if (res?.error) setError('Credenciais inválidas');
    else window.location.href = '/products';
  }

  return (
    <main className="max-w-sm mx-auto p-8 space-y-4">
      <h1 className="text-2xl font-semibold">Entrar</h1>

      {params.get('signup') === 'ok' && (
        <p className="p-2 bg-green-100 border">Conta criada – faça login.</p>
      )}
      {error && <p className="p-2 bg-red-100 border">{error}</p>}

      <form onSubmit={onSubmit} className="space-y-3">
        <input name="email"    type="email"    placeholder="E-mail"   required className="border p-2 w-full"/>
        <input name="password" type="password" placeholder="Password" required className="border p-2 w-full"/>
        <button className="bg-blue-600 text-white px-4 py-2 w-full">Entrar</button>
      </form>

      <p className="text-sm">
        Não tem conta? <a href="/signup" className="underline">Registar</a>
      </p>
    </main>
  );
}
