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
        placeholder="Nome"
        defaultValue={product?.name ?? ''}
        required
        className="border p-2 w-full"
      />
      <textarea
        name="description"
        placeholder="Descrição"
        defaultValue={product?.description ?? ''}
        className="border p-2 w-full"
      />
      <input
        name="price"
        type="number"
        step="0.01"
        placeholder="Preço"
        defaultValue={product?.price ?? ''}
        required
        className="border p-2 w-full"
      />
      <button className="bg-blue-600 text-white px-4 py-2">
        {product ? 'Actualizar' : 'Criar'}
      </button>
    </form>
  );
}
