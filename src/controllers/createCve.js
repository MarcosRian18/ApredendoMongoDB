const fs = require('fs').promises;
const path = require('path');
const dotenv = require('dotenv')
const CVEModel = require('../models/cve');

dotenv.config()

async function importCVEsFromDirectory(directoryPath) {
  const files = await fs.readdir(directoryPath);

  for (const file of files) {
    const filePath = path.join(directoryPath, file);
    const stat = await fs.stat(filePath);
    console.log(stat)
    if (stat.isDirectory()) {
      await importCVEsFromDirectory(filePath);
    } else if (file.endsWith('.json')) {
      if (file !== 'recent_activities.json') { 
        try {
          const cveData = require(filePath);
          console.log(cveData);
          await CVEModel.create(cveData);
          console.log(`Inserido o arquivo ${file} no MongoDB.`);
        } catch (error) {
          console.error(`Erro ao inserir o arquivo ${file}`, error);
        }
      } else {
        console.log(`O arquivo ${file} foi ignorado.`);
      }
    }
  }
}

module.exports = {
  importCVEs: async (req, res) => {
    const cveMainDirectoryPath = process.env.CVE_DIRECTORY;
    console.log(importCVEsFromDirectory)

    try {
      await importCVEsFromDirectory(cveMainDirectoryPath);
      return res.status(200).json({ message: 'Importação concluída.' });
    } catch (error) {
      console.error('Erro ao importar os arquivos:', error);
      return res.status(500).json({ message: 'Erro no servidor.' });
    }
  },
  FindCve: async (req,res) => {
    const {id} = req.params;

    try {
      const cve = await CVEModel.findOne({'cveMetadata.cveId': id})
      if(cve){
        return res.status(200).json(cve)
      }else{
        return res.send({message: "Não foi possivel encontrar o CVE-ID especificado."})
      }
    } catch (error) {
      console.log("Ocorreu um erro: ", error)
    }
  }
};