import { signupAction } from './actions';

export default function SignUp() {
  return (
    <main className="max-w-sm mx-auto p-8 space-y-4">
      <h1 className="text-2xl font-semibold">Criar conta</h1>

      <form action={signupAction} className="space-y-3">
        <input name="name"     placeholder="Nome"      className="border p-2 w-full"/>
        <input name="email"    type="email"    placeholder="E-mail"   required className="border p-2 w-full"/>
        <input name="password" type="password" placeholder="Password" required className="border p-2 w-full"/>
        <button className="bg-blue-600 text-white px-4 py-2 w-full">Registar</button>
      </form>

      <p className="text-sm">
        Já tem conta? <a href="/login" className="underline">Entrar</a>
      </p>
    </main>
  );
}
