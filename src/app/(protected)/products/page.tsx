import { prisma } from '@/lib/prisma';
import Link from 'next/link';

export default async function ProductsPage() {
  const products = await prisma.product.findMany({ orderBy: { id: 'desc' } });

  return (
    <main className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4">Produtos</h1>

      <Link href="/products/new" className="underline mb-4 inline-block">
        + Novo produto
      </Link>

      <ul className="space-y-4">
        {products.map(p => (
          <li key={p.id} className="border p-4 rounded">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="font-medium">{p.name}</h2>
                <p className="text-sm text-gray-600">{p.description}</p>
              </div>
              <div className="text-right">
                <p className="font-mono">€ {p.price.toFixed(2)}</p>
                <Link
                  href={`/products/${p.id}`}
                  className="text-blue-500 underline ml-2"
                >
                  Editar
                </Link>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </main>
  );
}
