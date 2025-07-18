echo "Asignando hugepages..."
echo 1024 > /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

echo "Desactivando ASLR..."
echo 0 > /proc/sys/kernel/randomize_va_space

echo "Cargando módulos UIO genérico y VFIO..."
modprobe uio
modprobe uio_pci_generic
modprobe vfio-pci

PCI_ID=0000:0a:00.0   # tu tarjeta I211

echo "Unbind de la NIC (por si acaso)…"
dpdk/usertools/dpdk-devbind.py --unbind $PCI_ID

echo "Bind al driver uio_pci_generic…"
dpdk/usertools/dpdk-devbind.py --bind=uio_pci_generic $PCI_ID
# Si prefieres VFIO en lugar de uio_pci_generic, comenta la línea anterior y descomenta:
# dpdk/usertools/dpdk-devbind.py --bind=vfio-pci $PCI_ID

echo "Estado tras el bind:"
dpdk/usertools/dpdk-devbind.py --status
