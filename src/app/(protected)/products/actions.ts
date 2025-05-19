'use server';

import { prisma } from '@/lib/prisma';
import { revalidatePath } from 'next/cache';

// CRIAR
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

// ACTUALIZAR
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

// APAGAR
export async function deleteProduct(id: number) {
  await prisma.product.delete({ where: { id } });
  revalidatePath('/products');
}
