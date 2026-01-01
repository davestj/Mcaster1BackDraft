<?php
/**
 * /app/api/task-manager.php — Task Manager API (strict JSON)
 *
 * Routes:
 *   GET  ?action=live_status         Running tasks + recent completed
 *   GET  ?action=run_detail&run_id=N Full run detail
 *   GET  ?action=task_runs&task_id=X Run history for a task
 *   GET  ?action=delete_run&run_id=N Delete a run record (admin)
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$action = $_GET['action'] ?? $_POST['action'] ?? '';

if ($action === 'live_status') {
    $running = db_rows("SELECT r.id, r.task_id, r.started_at, r.status, LEFT(r.output_log, 2000) as output_log, t.name as task_name, t.priority FROM backdraft_task_runs r JOIN backdraft_tasks t ON t.task_id = r.task_id WHERE r.status = 'running' ORDER BY r.started_at DESC");
    $recent = db_rows("SELECT r.id, r.task_id, r.started_at, r.ended_at, r.status, r.error_msg, r.export_formats, t.name as task_name, t.priority FROM backdraft_task_runs r JOIN backdraft_tasks t ON t.task_id = r.task_id WHERE r.status != 'running' ORDER BY r.started_at DESC LIMIT 5");
    echo json_encode(['ok'=>true,'running'=>$running,'recent'=>$recent]); return;
}

if ($action === 'run_detail') {
    $run_id = (int)($_GET['run_id'] ?? 0);
    $run = db_row("SELECT id, task_id, started_at, ended_at, status, output_log, error_msg, summary_json, export_html, export_formats FROM backdraft_task_runs WHERE id = ?", [$run_id]);
    if (!$run) { echo json_encode(['ok'=>false,'error'=>'Not found']); return; }
    echo json_encode(['ok'=>true,'data'=>$run]); return;
}

if ($action === 'task_runs') {
    $task_id = $_GET['task_id'] ?? '';
    $runs = db_rows("SELECT id, task_id, started_at, ended_at, status, LEFT(output_log, 2000) as output_log, error_msg, export_formats FROM backdraft_task_runs WHERE task_id = ? ORDER BY started_at DESC LIMIT 10", [$task_id]);
    echo json_encode(['ok'=>true,'data'=>$runs]); return;
}

if ($action === 'delete_run') {
    if (!bd_is_admin()) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); return; }
    $run_id = (int)($_GET['run_id'] ?? 0);
    db_run("DELETE FROM backdraft_task_runs WHERE id = ?", [$run_id]);
    echo json_encode(['ok'=>true]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);
