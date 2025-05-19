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
