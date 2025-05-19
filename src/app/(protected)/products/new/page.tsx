import ProductForm from '@/components/ProductForm';

export default function NewProduct() {
  return (
    <main className="max-w-md mx-auto p-6">
      <h1 className="text-xl font-semibold mb-4">Adicionar produto</h1>
      <ProductForm />
    </main>
  );
}
