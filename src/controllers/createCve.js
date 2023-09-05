// Importações
const fs = require("fs").promises;
const fs2 = require("fs");
const path = require("path");
const dotenv = require("dotenv");
const CVEModel = require("../models/cve");

// Variáveis e constantes globais
const d_lastFilepath = {
  path: "",
  dir: "",
  year: "",
};
const d_currFilesArray = {
  files: "",
  dirs: "",
  years: "",
};
const dataControl = path.join(__dirname, "./controlData.json");
const cves = path.join(__dirname, "../cveList/cvelistV5-main/cves/");

// Pré execução de métodos
dotenv.config();

/*
 * Pega o último registro do mongo_db, e com base no
 * 'cveMetadata.cveId', constrói o caminho para o arquivo
 */
async function setLastFilepath() {
  let cveId = await CVEModel.db
    .collection("cves")
    .find()
    .sort({ _id: -1 })
    .limit(1)
    .toArray();
    if(cveId.length == 0){
       cveId = 'CVE-2023-40012'
       
    }else {
      cveId = cveId[0].cveMetadata.cveId;
    }
    
  
  let result = cveId.match(/CVE\-(\d{4})\-(\d+)/);
  let cves_dir = path.join(cves, result[1].toString());
  let cves_subdirs = fs2.readdirSync(cves_dir);
  let folder_prefix = result[2].match(/(\d).+/)[1];
  let p_dir = "";

  cves_subdirs.forEach((i) => {
    if (i.match(`\\b(${folder_prefix}).*`)) {
      let buffer = path.join(cves_dir, i, cveId + ".json");
      if (fs2.existsSync(buffer)) p_dir = buffer;
    }
  });
  d_lastFilepath.path = p_dir;
  d_lastFilepath.dir = path.dirname(p_dir);
  d_lastFilepath.year = path.dirname(d_lastFilepath.dir);
}

/*
 * Obtem alguns arrays indicando a partir de quais arquivos
 * a inserção no banco de dados deve ser iniciada.
 */
function getNextFilesArray() {
  function s_read(dir) {
    let buffer = null;
    buffer = fs2.readdirSync(path.join(dir, "..")).sort();
    buffer = buffer.slice(buffer.indexOf(path.basename(dir)) + 1);

    return buffer;
  }

  d_currFilesArray.files = s_read(d_lastFilepath.path);
  d_currFilesArray.dirs = s_read(d_lastFilepath.dir);
  d_currFilesArray.years = s_read(d_lastFilepath.year);
  // d_currFilesArray.years = d_currFilesArray.years.slice(
  //   d_currFilesArray.years.indexOf("recent_activities.json"),
  //   d_currFilesArray.years.indexOf("recent_activities.json")
  // );
}

async function uploadFiles(base, files) {
  files.forEach((e) => {
    const p_path = path.join(base, e);

    if (!fs2.statSync(p_path).isDirectory()) {
      const ctt = fs2.readFileSync(p_path, "utf-8");
      let ctt2 = JSON.parse(ctt);
      //... verifica se o arquivo existe no banco de dados e faz o upload
      // CVEModel.create(ctt2);
      const doc = new CVEModel(ctt2)
      doc.save()

      console.log(path.basename(p_path));
    } else {
      let buffer = fs2.readdirSync(p_path);
      uploadFiles(p_path, buffer);
    }
  });
}

/*
 * Executa o método principal, o main, e também os demais
 * métodos na ordem certa.
 */
async function main() {
  try {
    await setLastFilepath();
    getNextFilesArray();
    await uploadFiles(d_lastFilepath.dir, d_currFilesArray.files);
    await uploadFiles(d_lastFilepath.year, d_currFilesArray.dirs);
    await uploadFiles(cves, d_currFilesArray.years);
  } catch (e) {
    console.log("Um erro aconteceu aqui...");
    console.log(e);
  }
}

module.exports = {
  importCVEs: async (req, res) => {
    try {
      main();
      return res.status(200).json({ message: "Importação concluída." });
    } catch (error) {
      console.error("Erro ao importar os arquivos: ", error);
      return res.status(500).json({ message: "Erro no servidor." });
    }
  },
  FindCve: async (req, res) => {
    const { id } = req.params;

    try {
      const cve = await CVEModel.findOne({ "cveMetadata.cveId": id });
      if (cve) {
        return res.status(200).json(cve);
      } else {
        return res.send({
          message: "Não foi possivel encontrar o CVE-ID especificado.",
        });
      }
    } catch (error) {
      console.log("Ocorreu um erro: ", error);
    }
  },
};
