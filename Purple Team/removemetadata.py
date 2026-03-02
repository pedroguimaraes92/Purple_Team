import os
from PIL import Image
import ffmpeg
from PyPDF2 import PdfReader, PdfWriter
from docx import Document

def remove_image_metadata(image_path, output_path):
    """Remove metadados de uma imagem."""
    try:
        with Image.open(image_path) as img:
            img.save(output_path, format=img.format)
            print(f"Metadados removidos da imagem: {output_path}")
    except Exception as e:
        print(f"Erro ao processar imagem: {e}")

def remove_video_metadata(video_path, output_path):
    """Remove metadados de um vídeo."""
    try:
        ffmpeg.input(video_path).output(output_path, map_metadata=-1).run(quiet=True, overwrite_output=True)
        print(f"Metadados removidos do vídeo: {output_path}")
    except Exception as e:
        print(f"Erro ao processar vídeo: {e}")

def remove_pdf_metadata(pdf_path, output_path):
    """Remove metadados de um PDF."""
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # Remover metadados
        writer._metadata = None  # Resetar metadados
        writer.add_metadata({})  # Adicionar um metadado vazio

        with open(output_path, "wb") as out_file:
            writer.write(out_file)
        print(f"Metadados removidos do PDF: {output_path}")
    except Exception as e:
        print(f"Erro ao processar PDF: {e}")

def remove_docx_metadata(docx_path, output_path):
    """Remove metadados de um arquivo Word (.docx)."""
    try:
        doc = Document(docx_path)

        # Remover propriedades do documento
        core_properties = doc.core_properties
        core_properties.author = None
        core_properties.title = None
        core_properties.subject = None
        core_properties.comments = None
        core_properties.last_modified_by = None

        doc.save(output_path)
        print(f"Metadados removidos do arquivo Word: {output_path}")
    except Exception as e:
        print(f"Erro ao processar arquivo Word: {e}")

def main():
    file_path = input("Digite o caminho completo do arquivo (imagem, vídeo, PDF, Word): ").strip()
    if not os.path.exists(file_path):
        print("O arquivo não existe. Verifique o caminho e tente novamente.")
        return

    output_path = input("Digite o caminho para salvar o arquivo sem metadados: ").strip()
    ext = os.path.splitext(file_path)[1].lower()

    if ext in ['.jpg', '.jpeg', '.png']:
        remove_image_metadata(file_path, output_path)
    elif ext in ['.mp4', '.mkv', '.avi', '.mov']:
        remove_video_metadata(file_path, output_path)
    elif ext == '.pdf':
        remove_pdf_metadata(file_path, output_path)
    elif ext == '.docx':
        remove_docx_metadata(file_path, output_path)
    else:
        print("Formato de arquivo não suportado. Aceitamos imagens (.jpg, .jpeg, .png), vídeos (.mp4, .mkv, .avi, .mov), PDFs e documentos Word (.docx).")

if __name__ == "__main__":
    main()
