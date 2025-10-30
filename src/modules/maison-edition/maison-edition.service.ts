import { Injectable } from '@nestjs/common'; // Injectable permet à NestJS d'injecter ce service dans le controller
import { PrismaService } from '../../prisma/prisma.service'; // Notre service Prisma pour accéder à la base de données


import { CreateMaisonEditionDto } from './dto/create-maison-edition.dto';
import { UpdateMaisonEditionDto } from './dto/update-maison-edition.dto';

@Injectable()
export class MaisonEditionService {
  constructor(private prisma: PrismaService) {}        // Injection du service Prisma
  // create(createMaisonEditionDto: CreateMaisonEditionDto) {
  //   return 'This action adds a new maisonEdition';
  // }

   // Méthode pour créer une maison d'édition
  async create(data: { nom: string; email?: string; telephone?: string; adresse?: string; logo?: string }) {
    return this.prisma.maisonEdition.create({
      data, // On transmet directement les données reçues au create de Prisma
    });
  }

  
  // Méthode pour récupérer toutes les maisons d'édition
  async findAll() {
    return this.prisma.maisonEdition.findMany(); // findMany() récupère tous les enregistrements
  }

  // Méthode pour récupérer une maison d'édition par ID
  async findOne(id: string) {
    return this.prisma.maisonEdition.findUnique({
      where: { id }, // On cherche l'enregistrement dont l'ID correspond
    });
  }

  // Méthode pour mettre à jour une maison d'édition
  async update(id: string, data: Partial<{ nom: string; email: string; telephone: string; adresse: string; logo: string }>) {
    return this.prisma.maisonEdition.update({
      where: { id }, // On cible l'enregistrement par ID
      data,          // On met à jour avec les nouvelles données
    });
  }

  // Méthode pour supprimer une maison d'édition
  async remove(id: string) {
    return this.prisma.maisonEdition.delete({
      where: { id }, // On supprime l'enregistrement ciblé
    });
  }
  // findAll() {
  //   return `This action returns all maisonEdition`;
  // }

  // findOne(id: number) {
  //   return `This action returns a #${id} maisonEdition`;
  // }

  // update(id: number, updateMaisonEditionDto: UpdateMaisonEditionDto) {
  //   return `This action updates a #${id} maisonEdition`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} maisonEdition`;
  // }
}
