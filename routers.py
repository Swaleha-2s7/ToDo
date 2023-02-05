from fastapi import APIRouter, Body, Request, HTTPException, status
from model import TaskBase, TaskCreate, TaskUpdate
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

router = APIRouter()


@router.get('/', response_description="List all Tasks")
async def list_tasks(request: Request):
    Tasks = request.app.mongodb['tasks']
    
    selector = {}
    tasks = []
    
    async for task in Tasks.find(selector):
        task = TaskBase(**task)
        tasks.append(task)

    return tasks


@router.post('/', response_description="Create a Task")
async def create_task(request: Request, task: TaskCreate=Body(...)):
    Tasks = request.app.mongodb['tasks']
    
    task = task.dict(by_alias=True)
    
    if (task_exist := await Tasks.find_one({'title': task['title'] })) is not None:
        raise HTTPException(status_code=404, detail=f"Task {task['name']} already exist.")
    
    new_task = await Tasks.insert_one(task)
    
    if (created_task := await Tasks.find_one({'_id': new_task.inserted_id})) is not None:
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=jsonable_encoder(created_task))
        
    raise HTTPException(status_code=400, details="something went wrong/ Bad request")


@router.patch('/{id}', response_description="Update a Task")
async def update_task(id:str, request: Request, task: TaskUpdate=Body(...)):
    print(task)
    Tasks = request.app.mongodb['tasks']
    task = task.dict(exclude_unset=True, by_alias=True)
    
    if 'title' in task:
        if len(task['title']) == 0:
            raise HTTPException(status_code=400, detail=f"Task title cannot be empty.")

    if (task_exist := await Tasks.find_one({"_id": id})) is None:
        raise HTTPException(status_code=404, detail=f"Task with ID:{id} not found.")
    
    updated_result = await Tasks.update_one({"_id": id}, {"$set": task})

    if updated_result.modified_count == 1:
        if (updated_result := await Tasks.find_one({"_id": id})) is not None:
            return updated_result

    raise HTTPException(status_code=400, detail=f"Fail to update task.")

