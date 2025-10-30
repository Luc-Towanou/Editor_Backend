import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AuteurService } from './auteur.service';
import { CreateAuteurDto } from './dto/create-auteur.dto';
import { UpdateAuteurDto } from './dto/update-auteur.dto';

@Controller('auteur')
export class AuteurController {
  constructor(private readonly auteurService: AuteurService) {}

  @Post()
  create(@Body() createAuteurDto: CreateAuteurDto) {
    return this.auteurService.create(createAuteurDto);
  }

  @Get()
  findAll() {
    return this.auteurService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.auteurService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuteurDto: UpdateAuteurDto) {
    return this.auteurService.update(+id, updateAuteurDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.auteurService.remove(+id);
  }
}
