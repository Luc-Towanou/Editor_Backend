-- CreateEnum
CREATE TYPE "Role" AS ENUM ('admin', 'editeur', 'auteur', 'libraire');

-- CreateEnum
CREATE TYPE "StatutUser" AS ENUM ('inactif', 'actif', 'suspendu', 'bloque', 'supprime', 'en_attente');

-- CreateEnum
CREATE TYPE "Format" AS ENUM ('broché', 'ebook', 'audiobook');

-- CreateEnum
CREATE TYPE "StatutLivre" AS ENUM ('en_preparation', 'publie', 'epuise', 'retire');

-- CreateEnum
CREATE TYPE "StatutCommande" AS ENUM ('en_attente', 'en_livraison', 'livree', 'annulee');

-- CreateEnum
CREATE TYPE "TypeBordereau" AS ENUM ('livraison', 'retour');

-- CreateEnum
CREATE TYPE "TypeNotification" AS ENUM ('stock', 'commande', 'systeme', 'info');

-- CreateEnum
CREATE TYPE "StatutPaiement" AS ENUM ('en_attente', 'paye');

-- CreateEnum
CREATE TYPE "Canal" AS ENUM ('librairie', 'direct', 'autre');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "nom" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "mot_de_passe" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "telephone" TEXT,
    "statut" "StatutUser" NOT NULL DEFAULT 'actif',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Auteur" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "bio" TEXT,
    "nationalite" TEXT,
    "photo" TEXT,
    "taux_royalties" DOUBLE PRECISION DEFAULT 10.0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Auteur_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Livre" (
    "id" TEXT NOT NULL,
    "titre" TEXT NOT NULL,
    "isbn" TEXT NOT NULL,
    "resume" TEXT,
    "prix_public" DOUBLE PRECISION NOT NULL,
    "date_publication" TIMESTAMP(3),
    "categorie" TEXT,
    "format" "Format" NOT NULL,
    "statut" "StatutLivre" NOT NULL,
    "couverture" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Livre_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LivreAuteur" (
    "id" TEXT NOT NULL,
    "livre_id" TEXT NOT NULL,
    "auteur_id" TEXT NOT NULL,

    CONSTRAINT "LivreAuteur_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Stock" (
    "id" TEXT NOT NULL,
    "livre_id" TEXT NOT NULL,
    "quantite_disponible" INTEGER NOT NULL,
    "seuil_alerte" INTEGER,
    "emplacement" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Stock_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Librairie" (
    "id" TEXT NOT NULL,
    "nom" TEXT NOT NULL,
    "contact" TEXT,
    "email" TEXT,
    "telephone" TEXT,
    "adresse" TEXT,
    "remise" DOUBLE PRECISION DEFAULT 0.0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Librairie_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Commande" (
    "id" TEXT NOT NULL,
    "librairie_id" TEXT NOT NULL,
    "statut" "StatutCommande" NOT NULL DEFAULT 'en_attente',
    "date_commande" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "total" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Commande_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CommandeLivre" (
    "id" TEXT NOT NULL,
    "commande_id" TEXT NOT NULL,
    "livre_id" TEXT NOT NULL,
    "quantite" INTEGER NOT NULL,
    "prix_unitaire" DOUBLE PRECISION NOT NULL,
    "sous_total" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "CommandeLivre_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vente" (
    "id" TEXT NOT NULL,
    "livre_id" TEXT NOT NULL,
    "quantite" INTEGER NOT NULL,
    "montant_total" DOUBLE PRECISION NOT NULL,
    "canal" "Canal" NOT NULL,
    "date_vente" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Vente_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Royalties" (
    "id" TEXT NOT NULL,
    "auteur_id" TEXT NOT NULL,
    "livre_id" TEXT NOT NULL,
    "periode" TEXT NOT NULL,
    "ventes_total" INTEGER NOT NULL,
    "montant_du" DOUBLE PRECISION NOT NULL,
    "statut" "StatutPaiement" NOT NULL DEFAULT 'en_attente',
    "date_paiement" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Royalties_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Bordereau" (
    "id" TEXT NOT NULL,
    "commande_id" TEXT NOT NULL,
    "type" "TypeBordereau" NOT NULL,
    "numero" TEXT NOT NULL,
    "date_emission" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "fichier_pdf" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Bordereau_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "titre" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "type" "TypeNotification" NOT NULL,
    "lu" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Auteur_user_id_key" ON "Auteur"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "Livre_isbn_key" ON "Livre"("isbn");

-- CreateIndex
CREATE UNIQUE INDEX "Stock_livre_id_key" ON "Stock"("livre_id");

-- CreateIndex
CREATE UNIQUE INDEX "Bordereau_numero_key" ON "Bordereau"("numero");

-- AddForeignKey
ALTER TABLE "Auteur" ADD CONSTRAINT "Auteur_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LivreAuteur" ADD CONSTRAINT "LivreAuteur_livre_id_fkey" FOREIGN KEY ("livre_id") REFERENCES "Livre"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LivreAuteur" ADD CONSTRAINT "LivreAuteur_auteur_id_fkey" FOREIGN KEY ("auteur_id") REFERENCES "Auteur"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Stock" ADD CONSTRAINT "Stock_livre_id_fkey" FOREIGN KEY ("livre_id") REFERENCES "Livre"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Commande" ADD CONSTRAINT "Commande_librairie_id_fkey" FOREIGN KEY ("librairie_id") REFERENCES "Librairie"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CommandeLivre" ADD CONSTRAINT "CommandeLivre_commande_id_fkey" FOREIGN KEY ("commande_id") REFERENCES "Commande"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CommandeLivre" ADD CONSTRAINT "CommandeLivre_livre_id_fkey" FOREIGN KEY ("livre_id") REFERENCES "Livre"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vente" ADD CONSTRAINT "Vente_livre_id_fkey" FOREIGN KEY ("livre_id") REFERENCES "Livre"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Royalties" ADD CONSTRAINT "Royalties_auteur_id_fkey" FOREIGN KEY ("auteur_id") REFERENCES "Auteur"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Royalties" ADD CONSTRAINT "Royalties_livre_id_fkey" FOREIGN KEY ("livre_id") REFERENCES "Livre"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Bordereau" ADD CONSTRAINT "Bordereau_commande_id_fkey" FOREIGN KEY ("commande_id") REFERENCES "Commande"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
