import { prisma } from '@/lib/prisma';
import ProductForm from '@/components/ProductForm';
import { notFound } from 'next/navigation';

export default async function EditProduct({ params: { id } }: { params: { id: string } }) {
  const product = await prisma.product.findUnique({ where: { id: Number(id) } });
  if (!product) notFound();

  return (
    <main className="max-w-md mx-auto p-6">
      <h1 className="text-xl font-semibold mb-4">Editar produto</h1>
      <ProductForm product={product} />
    </main>
  );
}
