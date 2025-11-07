<?php
/**
 * Minimal XLSX reader for SSL Expiry Manager import previews.
 * Supports basic worksheets with shared strings and inline text.
 */
if(!class_exists('SimpleXLSX')){
class SimpleXLSX {
    private $rows = [];
    private $error = '';
    private static $last_error = '';

    public static function parse($filename){
        $instance = new self();
        if($instance->parseFile($filename)){
            return $instance;
        }
        self::$last_error = $instance->getError();
        return false;
    }

    public static function parseError(){
        return self::$last_error;
    }

    public function rows(){
        return $this->rows;
    }

    private function getError(){
        return $this->error ?: 'Unknown XLSX parsing error';
    }

    private function parseFile($filename){
        if(!class_exists('ZipArchive')){
            $this->error = 'ZipArchive extension is required';
            return false;
        }
        $zip = new ZipArchive();
        if($zip->open($filename) !== true){
            $this->error = 'Unable to open XLSX file';
            return false;
        }
        $sharedStrings = $this->extractSharedStrings($zip);
        $sheetPath = $this->locateFirstWorksheet($zip);
        if($sheetPath === null){
            $this->error = 'Worksheet not found in XLSX';
            $zip->close();
            return false;
        }
        $sheetXml = $zip->getFromName($sheetPath);
        $zip->close();
        if($sheetXml === false){
            $this->error = 'Worksheet data missing';
            return false;
        }
        $sheet = @simplexml_load_string($sheetXml);
        if(!$sheet || !isset($sheet->sheetData)){
            $this->error = 'Worksheet XML invalid';
            return false;
        }
        $rows = [];
        foreach($sheet->sheetData->row as $row){
            $current = [];
            foreach($row->c as $cell){
                $current[] = $this->parseCell($cell, $sharedStrings);
            }
            $rows[] = $current;
        }
        $this->rows = $rows;
        return true;
    }

    private function extractSharedStrings(ZipArchive $zip){
        $strings = [];
        $xml = $zip->getFromName('xl/sharedStrings.xml');
        if($xml === false){
            return $strings;
        }
        $doc = @simplexml_load_string($xml);
        if(!$doc){
            return $strings;
        }
        foreach($doc->si as $si){
            $text = '';
            if(isset($si->t)){
                $text = (string)$si->t;
            } elseif(isset($si->r)){
                foreach($si->r as $run){
                    if(isset($run->t)){
                        $text .= (string)$run->t;
                    }
                }
            }
            $strings[] = $text;
        }
        return $strings;
    }

    private function locateFirstWorksheet(ZipArchive $zip){
        if($zip->locateName('xl/worksheets/sheet1.xml') !== false){
            return 'xl/worksheets/sheet1.xml';
        }
        $workbookXml = $zip->getFromName('xl/workbook.xml');
        if($workbookXml === false){
            return null;
        }
        $workbook = @simplexml_load_string($workbookXml);
        if(!$workbook || !isset($workbook->sheets->sheet[0])){
            return null;
        }
        $sheetId = (string)$workbook->sheets->sheet[0]['r:id'];
        $relsXml = $zip->getFromName('xl/_rels/workbook.xml.rels');
        if($relsXml === false){
            return null;
        }
        $rels = @simplexml_load_string($relsXml);
        if(!$rels){
            return null;
        }
        foreach($rels->Relationship as $rel){
            if((string)$rel['Id'] === $sheetId){
                $target = (string)$rel['Target'];
                if(strpos($target, 'worksheets/') !== false){
                    if(strpos($target, '../') === 0){
                        $target = substr($target, 3);
                    }
                    return 'xl/'.$target;
                }
            }
        }
        return null;
    }

    private function parseCell(SimpleXMLElement $cell, array $sharedStrings){
        $type = (string)$cell['t'];
        if($type === 's'){ // shared string
            $idx = isset($cell->v) ? intval($cell->v) : -1;
            return ($idx >=0 && isset($sharedStrings[$idx])) ? $sharedStrings[$idx] : '';
        }
        if($type === 'inlineStr' && isset($cell->is->t)){
            return (string)$cell->is->t;
        }
        if(isset($cell->v)){
            return (string)$cell->v;
        }
        return '';
    }
}
}
