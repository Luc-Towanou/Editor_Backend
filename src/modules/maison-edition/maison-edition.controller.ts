// import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';

import { Controller, Get, Post, Body, Param, Put, Delete } from '@nestjs/common';
import { MaisonEditionService } from './maison-edition.service';
import { CreateMaisonEditionDto } from './dto/create-maison-edition.dto';
import { UpdateMaisonEditionDto } from './dto/update-maison-edition.dto';

@Controller('maison-edition')
// export class MaisonEditionController {
//   constructor(private readonly maisonEditionService: MaisonEditionService) {}

  // @Post()
  // create(@Body() createMaisonEditionDto: CreateMaisonEditionDto) {
  //   return this.maisonEditionService.create(createMaisonEditionDto);
  // }

  // @Get()
  // findAll() {
  //   return this.maisonEditionService.findAll();
  // }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.maisonEditionService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateMaisonEditionDto: UpdateMaisonEditionDto) {
  //   return this.maisonEditionService.update(+id, updateMaisonEditionDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.maisonEditionService.remove(+id);
  // }


@Controller('maison-edition') // Préfixe de route : toutes les routes commenceront par /maison-edition
export class MaisonEditionController {
  constructor(private readonly maisonService: MaisonEditionService) {} // Injection du service

  // Route POST /maison-edition → Créer une nouvelle maison
  @Post()
  async create(@Body() data: { nom: string; email?: string; telephone?: string; adresse?: string; logo?: string }) {
    return this.maisonService.create(data);
  }

  // Route GET /maison-edition → Récupérer toutes les maisons
  @Get()
  async findAll() {
    return this.maisonService.findAll();
  }

  // Route GET /maison-edition/:id → Récupérer une maison par ID
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.maisonService.findOne(id);
  }

  // Route PUT /maison-edition/:id → Mettre à jour une maison
  @Put(':id')
  async update(@Param('id') id: string, @Body() data: Partial<{ nom: string; email: string; telephone: string; adresse: string; logo: string }>) {
    return this.maisonService.update(id, data);
  }

  // Route DELETE /maison-edition/:id → Supprimer une maison
  @Delete(':id')
  async remove(@Param('id') id: string) {
    return this.maisonService.remove(id);
  }
}

// }
