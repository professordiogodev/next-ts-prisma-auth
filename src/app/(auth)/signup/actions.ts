'use server';
import { prisma } from '@/lib/prisma';
import { hashPassword } from '@/lib/hash';
import { redirect } from 'next/navigation';

export async function signupAction(fd: FormData) {
  const email = fd.get('email') as string;
  const pw    = fd.get('password') as string;
  const name  = fd.get('name') as string | null;

  if (await prisma.user.findUnique({ where: { email } }))
    throw new Error('E-mail já registado');

  await prisma.user.create({
    data: { email, name, passwordHash: await hashPassword(pw) },
  });

  redirect('/login?signup=ok');
}
