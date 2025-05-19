import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
  await prisma.product.createMany({
    data: [
      { name: 'Chá',  description: 'Chá verde', price: 4.90 },
      { name: 'Bolo', description: 'Chocolate', price: 12.50 },
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
