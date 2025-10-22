from boto3.session import Session
import botocore

session = Session(profile_name='workshop-reader')
s3 = session.client('s3')
bucket_name = 'gio-exemplo-bucket'
region = 'sa-east-1'
arquivo_local = 'arquivo.txt'
chave_objeto = 'meuarquivo.txt'

def criar_bucket():
    try:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )
        print(f'Bucket criado com sucesso: {bucket_name}')
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(f'O bucket já existe: {bucket_name}')
        else:
            print(f'Erro ao criar bucket: {error.response["Error"]["Message"]}')

def upload_arquivo():
    try:
        s3.upload_file(arquivo_local, bucket_name, chave_objeto)
        print(f'Arquivo "{arquivo_local}" enviado para o bucket "{bucket_name}" como "{chave_objeto}"')
    except Exception as e:
        print(f'Erro no upload do arquivo: {e}')

def listar_arquivos():
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        print('Arquivos no bucket:')
        if 'Contents' in response:
            for obj in response['Contents']:
                print(f'- {obj["Key"]}')
        else:
            print('O bucket está vazio.')
    except Exception as e:
        print(f'Erro ao listar arquivos: {e}')

def apagar_bucket():
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            for obj in response['Contents']:
                s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                print(f'Arquivo removido: {obj["Key"]}')
        s3.delete_bucket(Bucket=bucket_name)
        print(f'Bucket removido: {bucket_name}')
    except Exception as e:
        print(f'Erro ao apagar bucket: {e}')

def listar_buckets():
    try:
        response = s3.list_buckets()
        print('Buckets disponíveis:')
        if 'Buckets' in response:
            for bucket in response['Buckets']:
                print(f'- {bucket["Name"]}')
        else:
            print('Nenhum bucket encontrado.')
    except Exception as e:
        print(f'Erro ao listar buckets: {e}')



#criar_bucket()
#upload_arquivo()
#listar_arquivos()
#apagar_bucket()
listar_buckets()
